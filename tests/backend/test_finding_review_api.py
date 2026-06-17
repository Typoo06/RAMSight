# Finding review workflow API tests.

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import get_db
from app.main import app
from app.models import AnalystNote, AnalysisJob, Base, Case, Evidence, RiskFinding


@pytest.fixture()
def client_context():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    try:
        yield TestClient(app), TestingSessionLocal
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)


def seed_finding(db, case_code: str, title: str = "Suspicious executable memory region"):
    case = Case(case_code=case_code, name=case_code)
    db.add(case)
    db.flush()
    evidence = Evidence(case_id=case.id, original_filename="memory.raw", os_family="windows")
    db.add(evidence)
    db.flush()
    job = AnalysisJob(case_id=case.id, evidence_id=evidence.id, status="completed", os_family="windows")
    db.add(job)
    db.flush()
    finding = RiskFinding(
        analysis_job_id=job.id,
        evidence_id=evidence.id,
        os_family="windows",
        os_scope="windows",
        source_plugin="windows.malfind",
        rule_id="MEMORY_REGION_EXECUTABLE",
        rule_name="Suspicious executable memory region",
        category="memory_region",
        severity="high",
        score=9,
        title=title,
        artifact_type="memory_region_artifacts",
        artifact_id=str(uuid4()),
    )
    db.add(finding)
    db.flush()
    return case, evidence, job, finding


def test_patch_review_updates_finding_and_effective_severity(client_context) -> None:
    client, session_factory = client_context
    db = session_factory()
    try:
        _, _, _, finding = seed_finding(db, "CASE-REVIEW-1")
        db.commit()
        finding_id = str(finding.id)
    finally:
        db.close()

    response = client.patch(
        f"/api/v1/risk-findings/{finding_id}/review",
        json={
            "review_status": "reviewed",
            "analyst_verdict": "false_positive",
            "severity_override": "low",
            "reviewed_by_name": "Analyst One",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["review_status"] == "reviewed"
    assert payload["analyst_verdict"] == "false_positive"
    assert payload["severity"] == "high"
    assert payload["severity_override"] == "low"
    assert payload["effective_severity"] == "low"
    assert payload["reviewed_at"] is not None
    assert payload["review_updated_at"] is not None
    assert payload["reviewed_by_name"] == "Analyst One"


def test_invalid_review_values_are_rejected(client_context) -> None:
    client, session_factory = client_context
    db = session_factory()
    try:
        _, _, _, finding = seed_finding(db, "CASE-REVIEW-INVALID")
        db.commit()
        finding_id = str(finding.id)
    finally:
        db.close()

    bad_status = client.patch(f"/api/v1/risk-findings/{finding_id}/review", json={"review_status": "closed"})
    bad_verdict = client.patch(f"/api/v1/risk-findings/{finding_id}/review", json={"analyst_verdict": "malware"})
    bad_severity = client.patch(f"/api/v1/risk-findings/{finding_id}/review", json={"severity_override": "severe"})

    assert bad_status.status_code == 400
    assert bad_verdict.status_code == 400
    assert bad_severity.status_code == 400


def test_patch_review_note_creates_linked_note(client_context) -> None:
    client, session_factory = client_context
    db = session_factory()
    try:
        _, _, _, finding = seed_finding(db, "CASE-REVIEW-NOTE")
        db.commit()
        finding_id = str(finding.id)
    finally:
        db.close()

    response = client.patch(
        f"/api/v1/risk-findings/{finding_id}/review",
        json={"review_status": "investigating", "reviewed_by_name": "Analyst Two", "note": "Checking parent process."},
    )
    assert response.status_code == 200

    notes = client.get(f"/api/v1/risk-findings/{finding_id}/notes")
    assert notes.status_code == 200
    items = notes.json()["items"]
    assert len(items) == 1
    assert items[0]["content"] == "Checking parent process."
    assert items[0]["author_name"] == "Analyst Two"
    assert items[0]["note_type"] == "finding_review"
    assert items[0]["risk_finding_id"] == finding_id


def test_post_and_list_notes_are_scoped_to_finding(client_context) -> None:
    client, session_factory = client_context
    db = session_factory()
    try:
        _, _, _, finding_one = seed_finding(db, "CASE-REVIEW-SCOPE-1")
        case_two, evidence_two, job_two, finding_two = seed_finding(db, "CASE-REVIEW-SCOPE-2")
        db.add(
            AnalystNote(
                case_id=case_two.id,
                evidence_id=evidence_two.id,
                analysis_job_id=job_two.id,
                risk_finding_id=finding_two.id,
                note_type="finding_review",
                body="Different finding note.",
            )
        )
        db.commit()
        finding_one_id = str(finding_one.id)
    finally:
        db.close()

    created = client.post(
        f"/api/v1/risk-findings/{finding_one_id}/notes",
        json={"content": "Confirmed suspicious, needs validation.", "author_name": "Analyst Three"},
    )
    assert created.status_code == 201

    listed = client.get(f"/api/v1/risk-findings/{finding_one_id}/notes")
    assert listed.status_code == 200
    items = listed.json()["items"]
    assert len(items) == 1
    assert items[0]["content"] == "Confirmed suspicious, needs validation."

    missing = client.post(
        "/api/v1/risk-findings/00000000-0000-0000-0000-000000000000/notes",
        json={"content": "No finding."},
    )
    assert missing.status_code == 404


def test_blank_note_create_is_rejected(client_context) -> None:
    client, session_factory = client_context
    db = session_factory()
    try:
        _, _, _, finding = seed_finding(db, "CASE-REVIEW-BLANK")
        db.commit()
        finding_id = str(finding.id)
    finally:
        db.close()

    response = client.post(f"/api/v1/risk-findings/{finding_id}/notes", json={"content": "   "})

    assert response.status_code in {400, 422}


def test_list_risk_findings_filters_by_review_status_and_effective_severity(client_context) -> None:
    client, session_factory = client_context
    db = session_factory()
    try:
        _, _, job, finding_one = seed_finding(db, "CASE-REVIEW-FILTER-1", title="One")
        _, _, _, finding_two = seed_finding(db, "CASE-REVIEW-FILTER-2", title="Two")
        finding_one.review_status = "reviewed"
        finding_one.analyst_verdict = "true_positive"
        finding_one.severity_override = "critical"
        finding_two.review_status = "investigating"
        db.commit()
        job_id = str(job.id)
    finally:
        db.close()

    by_status = client.get("/api/v1/risk-findings", params={"review_status": "reviewed"})
    by_effective = client.get("/api/v1/risk-findings", params={"severity_effective": "critical"})
    by_job = client.get("/api/v1/risk-findings", params={"job_id": job_id, "review_status": "reviewed"})

    assert by_status.status_code == 200
    assert [item["title"] for item in by_status.json()["items"]] == ["One"]
    assert by_effective.status_code == 200
    assert [item["title"] for item in by_effective.json()["items"]] == ["One"]
    assert by_job.status_code == 200
    assert [item["title"] for item in by_job.json()["items"]] == ["One"]

def test_risk_finding_export_json_and_csv_are_filterable(client_context) -> None:
    client, session_factory = client_context
    db = session_factory()
    try:
        _, _, job, finding_one = seed_finding(db, "CASE-FINDING-EXPORT-1", title="Memory region candidate")
        _, _, _, finding_two = seed_finding(db, "CASE-FINDING-EXPORT-2", title="Other case finding")
        finding_two.category = "network"
        db.commit()
        job_id = str(job.id)
    finally:
        db.close()

    json_response = client.get("/api/v1/risk-findings/export.json", params={"job_id": job_id, "category": "memory_region"})
    csv_response = client.get("/api/v1/risk-findings/export.csv", params={"job_id": job_id})

    assert json_response.status_code == 200
    assert json_response.headers["content-disposition"] == 'attachment; filename="risk_findings.json"'
    payload = json_response.json()
    assert payload["kind"] == "risk_findings"
    assert payload["count"] == 1
    assert payload["items"][0]["title"] == "Memory region candidate"
    assert csv_response.status_code == 200
    assert csv_response.headers["content-disposition"] == 'attachment; filename="risk_findings.csv"'
    assert "Memory region candidate" in csv_response.text
    assert "Other case finding" not in csv_response.text


def test_risk_finding_export_rejects_unsupported_format(client_context) -> None:
    client, _ = client_context

    response = client.get("/api/v1/risk-findings/export.xml")

    assert response.status_code == 400
    assert response.json()["detail"] == "unsupported export format"
