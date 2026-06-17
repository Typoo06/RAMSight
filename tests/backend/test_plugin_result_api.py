# Plugin result API tests.

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import get_db
from app.main import app
from app.models import AnalysisJob, Base, Case, Evidence, PluginResult


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


def seed_job(db, case_code: str):
    case = Case(case_code=case_code, name=case_code)
    db.add(case)
    db.flush()
    evidence = Evidence(case_id=case.id, original_filename="memory.raw", os_family="windows")
    db.add(evidence)
    db.flush()
    job = AnalysisJob(case_id=case.id, evidence_id=evidence.id, status="completed", os_family="windows")
    db.add(job)
    db.flush()
    return evidence, job


def seed_plugin_result(db, job: AnalysisJob, evidence: Evidence, plugin_name: str, status: str = "completed") -> PluginResult:
    plugin_result = PluginResult(
        analysis_job_id=job.id,
        evidence_id=evidence.id,
        os_family="windows",
        plugin_profile="windows_memory_yara",
        plugin_name=plugin_name,
        source_plugin=plugin_name,
        status=status,
        raw_output_bucket="raw-outputs",
        raw_output_key=f"case-a/job-b/raw/{plugin_name}.json",
        parsed_output_bucket="raw-outputs",
        parsed_output_key=f"case-a/job-b/parsed/{plugin_name}.json",
        parsed_record_count=3,
        duration_ms=120,
    )
    db.add(plugin_result)
    db.flush()
    return plugin_result


def test_plugin_results_list_filters_by_job_status_and_plugin_name(client_context) -> None:
    client, session_factory = client_context
    db = session_factory()
    try:
        evidence_one, job_one = seed_job(db, "CASE-PLUGIN-1")
        evidence_two, job_two = seed_job(db, "CASE-PLUGIN-2")
        first = seed_plugin_result(db, job_one, evidence_one, "windows.pslist")
        seed_plugin_result(db, job_one, evidence_one, "windows.malfind", status="failed")
        seed_plugin_result(db, job_two, evidence_two, "windows.pslist")
        db.commit()
        job_one_id = str(job_one.id)
        first_id = str(first.id)
    finally:
        db.close()

    response = client.get(f"/api/v1/analysis-jobs/{job_one_id}/plugin-results", params={"status": "completed"})
    assert response.status_code == 200
    payload = response.json()
    assert [item["id"] for item in payload["items"]] == [first_id]
    assert payload["total"] == 1
    assert payload["limit"] == 100
    assert payload["offset"] == 0

    plugin_response = client.get(
        f"/api/v1/analysis-jobs/{job_one_id}/plugin-results",
        params={"plugin_name": "windows.pslist", "limit": 1, "offset": 0},
    )
    assert plugin_response.status_code == 200
    item = plugin_response.json()["items"][0]
    assert item["plugin_name"] == "windows.pslist"
    assert item["raw_output_key"].endswith("windows.pslist.json")
    assert plugin_response.json()["total"] == 1
    assert plugin_response.json()["limit"] == 1
    assert plugin_response.json()["offset"] == 0
    assert "stdout" not in item
    assert "stderr" not in item


def test_plugin_result_export_json_uses_metadata_only(client_context) -> None:
    client, session_factory = client_context
    db = session_factory()
    try:
        evidence, job = seed_job(db, "CASE-PLUGIN-EXPORT")
        seed_plugin_result(db, job, evidence, "windows.pslist")
        seed_plugin_result(db, job, evidence, "windows.malfind", status="failed")
        db.commit()
        job_id = str(job.id)
    finally:
        db.close()

    response = client.get(f"/api/v1/analysis-jobs/{job_id}/plugin-results/export.json")

    assert response.status_code == 200
    assert response.headers["content-disposition"] == 'attachment; filename="plugin_results.json"'
    payload = response.json()
    assert payload["kind"] == "plugin_results"
    assert payload["count"] == 2
    assert {item["plugin_name"] for item in payload["items"]} == {"windows.pslist", "windows.malfind"}
    assert "stdout" not in payload["items"][0]
    assert "stderr" not in payload["items"][0]


def test_plugin_result_detail_and_missing_id(client_context) -> None:
    client, session_factory = client_context
    db = session_factory()
    try:
        evidence, job = seed_job(db, "CASE-PLUGIN-DETAIL")
        plugin_result = seed_plugin_result(db, job, evidence, "windows.vadyarascan", status="skipped")
        db.commit()
        plugin_result_id = str(plugin_result.id)
    finally:
        db.close()

    response = client.get(f"/api/v1/plugin-results/{plugin_result_id}")
    assert response.status_code == 200
    assert response.json()["status"] == "skipped"

    missing = client.get("/api/v1/plugin-results/00000000-0000-0000-0000-000000000000")
    assert missing.status_code == 404


def test_plugin_results_validate_job_exists(client_context) -> None:
    client, _ = client_context

    response = client.get("/api/v1/analysis-jobs/00000000-0000-0000-0000-000000000000/plugin-results")

    assert response.status_code == 404
