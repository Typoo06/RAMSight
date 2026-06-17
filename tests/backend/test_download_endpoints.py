# Generated-file download endpoint tests.

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import get_db
from app.main import app
from app.models import AnalysisJob, Base, Case, Evidence, PluginResult, Report
from app.storage.client import StorageObjectNotFoundError, StorageObjectStream, get_storage_client
from app.storage.keys import ioc_export_key, report_object_key


class FakeObjectResponse:

    def __init__(self, payload: bytes, content_type: str) -> None:
        self.payload = payload
        self.headers = {"Content-Length": str(len(payload)), "Content-Type": content_type}
        self.closed = False
        self.released = False

    def stream(self, chunk_size: int):
        for index in range(0, len(self.payload), chunk_size):
            yield self.payload[index:index + chunk_size]

    def close(self) -> None:
        self.closed = True

    def release_conn(self) -> None:
        self.released = True


class FakeStorageClient:

    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], tuple[bytes, str]] = {}
        self.requests: list[tuple[str, str]] = []

    def add_object(self, bucket: str, key: str, payload: bytes, content_type: str) -> None:
        self.objects[(bucket, key)] = (payload, content_type)

    def open_object_stream(self, bucket: str, object_key: str) -> StorageObjectStream:
        self.requests.append((bucket, object_key))
        try:
            payload, content_type = self.objects[(bucket, object_key)]
        except KeyError as exc:
            raise StorageObjectNotFoundError("storage object not found") from exc
        response = FakeObjectResponse(payload, content_type)
        return StorageObjectStream(
            bucket=bucket,
            key=object_key,
            response=response,
            size_bytes=len(payload),
            content_type=content_type,
        )


@pytest.fixture()
def client_context():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    fake_storage = FakeStorageClient()

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_storage_client] = lambda: fake_storage
    try:
        yield TestClient(app), TestingSessionLocal, fake_storage
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)


def seed_analysis_job(session_factory):
    db = session_factory()
    try:
        case = Case(case_code=f"CASE-{uuid4()}", name="Download test")
        db.add(case)
        db.flush()
        evidence = Evidence(case_id=case.id, original_filename="memory.raw", os_family="windows")
        db.add(evidence)
        db.flush()
        job = AnalysisJob(case_id=case.id, evidence_id=evidence.id, status="completed", os_family="windows")
        db.add(job)
        db.commit()
        db.refresh(case)
        db.refresh(evidence)
        db.refresh(job)
        return case, evidence, job
    finally:
        db.close()


def seed_report(session_factory, case: Case, evidence: Evidence, job: AnalysisJob, bucket: str = "reports", key: str | None = None):
    db = session_factory()
    try:
        report = Report(
            case_id=case.id,
            evidence_id=evidence.id,
            analysis_job_id=job.id,
            os_family="windows",
            report_type="technical",
            format="html",
            storage_bucket=bucket,
            storage_key=key or report_object_key(case.id, job.id, "technical_report.html"),
        )
        db.add(report)
        db.commit()
        db.refresh(report)
        return report
    finally:
        db.close()


def seed_plugin_result(session_factory, evidence: Evidence, job: AnalysisJob, bucket: str = "raw-outputs", key: str | None = None):
    db = session_factory()
    try:
        plugin_result = PluginResult(
            analysis_job_id=job.id,
            evidence_id=evidence.id,
            os_family="windows",
            plugin_profile="windows_default",
            plugin_name="windows.pslist",
            source_plugin="windows.pslist",
            status="completed",
            raw_output_bucket=bucket,
            raw_output_key=key or f"case-{job.case_id}/job-{job.id}/raw/windows_pslist.json",
            parsed_record_count=2,
        )
        db.add(plugin_result)
        db.commit()
        db.refresh(plugin_result)
        return plugin_result
    finally:
        db.close()


def test_report_download_returns_404_for_missing_report(client_context) -> None:
    client, _, fake_storage = client_context

    response = client.get(f"/api/v1/reports/{uuid4()}/download")

    assert response.status_code == 404
    assert fake_storage.requests == []


def test_report_download_streams_html_attachment(client_context) -> None:
    client, session_factory, fake_storage = client_context
    case, evidence, job = seed_analysis_job(session_factory)
    report = seed_report(session_factory, case, evidence, job)
    fake_storage.add_object("reports", report.storage_key, b"<html>RAMSight</html>", "text/html; charset=utf-8")

    response = client.get(f"/api/v1/reports/{report.id}/download")

    assert response.status_code == 200
    assert response.content == b"<html>RAMSight</html>"
    assert response.headers["content-disposition"] == 'attachment; filename="technical_report.html"'
    assert response.headers["content-type"].startswith("text/html")


def test_report_download_rejects_invalid_storage_metadata_before_object_access(client_context) -> None:
    client, session_factory, fake_storage = client_context
    case, evidence, job = seed_analysis_job(session_factory)
    report = seed_report(session_factory, case, evidence, job, bucket="evidence")

    response = client.get(f"/api/v1/reports/{report.id}/download")

    assert response.status_code == 400
    assert response.json()["detail"] == "report file metadata is invalid"
    assert fake_storage.requests == []


def test_report_download_handles_missing_storage_object_safely(client_context) -> None:
    client, session_factory, fake_storage = client_context
    case, evidence, job = seed_analysis_job(session_factory)
    report = seed_report(session_factory, case, evidence, job)

    response = client.get(f"/api/v1/reports/{report.id}/download")

    assert response.status_code == 404
    assert response.json()["detail"] == "Report file is not available yet."
    assert fake_storage.requests == [("reports", report.storage_key)]


def test_ioc_export_download_validates_job_exists(client_context) -> None:
    client, _, fake_storage = client_context

    response = client.get(f"/api/v1/analysis-jobs/{uuid4()}/iocs/export.json")

    assert response.status_code == 404
    assert fake_storage.requests == []


def test_ioc_export_download_returns_json_and_csv_attachments(client_context) -> None:
    client, session_factory, fake_storage = client_context
    case, _, job = seed_analysis_job(session_factory)
    json_key = ioc_export_key(case.id, job.id, "ioc_export.json")
    csv_key = ioc_export_key(case.id, job.id, "ioc_export.csv")
    fake_storage.add_object("raw-outputs", json_key, b'{"items": []}', "application/json")
    fake_storage.add_object("raw-outputs", csv_key, b"ioc_type,value\n", "text/csv; charset=utf-8")

    json_response = client.get(f"/api/v1/analysis-jobs/{job.id}/iocs/export.json")
    csv_response = client.get(f"/api/v1/analysis-jobs/{job.id}/iocs/export.csv")

    assert json_response.status_code == 200
    assert json_response.content == b'{"items": []}'
    assert json_response.headers["content-disposition"] == 'attachment; filename="ioc_export.json"'
    assert json_response.headers["content-type"].startswith("application/json")
    assert csv_response.status_code == 200
    assert csv_response.content == b"ioc_type,value\n"
    assert csv_response.headers["content-disposition"] == 'attachment; filename="ioc_export.csv"'
    assert csv_response.headers["content-type"].startswith("text/csv")


def test_ioc_export_download_returns_404_when_object_missing(client_context) -> None:
    client, session_factory, fake_storage = client_context
    case, _, job = seed_analysis_job(session_factory)
    expected_key = ioc_export_key(case.id, job.id, "ioc_export.json")

    response = client.get(f"/api/v1/analysis-jobs/{job.id}/iocs/export.json")

    assert response.status_code == 404
    assert response.json()["detail"] == "IOC export is not available for this analysis job."
    assert fake_storage.requests == [("raw-outputs", expected_key)]


def test_ioc_export_download_rejects_unsupported_format(client_context) -> None:
    client, session_factory, fake_storage = client_context
    _, _, job = seed_analysis_job(session_factory)

    response = client.get(f"/api/v1/analysis-jobs/{job.id}/iocs/export.xml")

    assert response.status_code == 400
    assert response.json()["detail"] == "unsupported IOC export format"
    assert fake_storage.requests == []

def test_plugin_raw_output_download_streams_db_referenced_object(client_context) -> None:
    client, session_factory, fake_storage = client_context
    _, evidence, job = seed_analysis_job(session_factory)
    plugin_result = seed_plugin_result(session_factory, evidence, job)
    fake_storage.add_object("raw-outputs", plugin_result.raw_output_key, b'{"rows": []}', "application/json")

    response = client.get(f"/api/v1/plugin-results/{plugin_result.id}/raw-output/download")

    assert response.status_code == 200
    assert response.content == b'{"rows": []}'
    assert response.headers["content-disposition"] == 'attachment; filename="windows_pslist_raw_output.json"'
    assert response.headers["content-type"].startswith("application/json")
    assert fake_storage.requests == [("raw-outputs", plugin_result.raw_output_key)]


def test_plugin_raw_output_download_rejects_invalid_bucket_before_object_access(client_context) -> None:
    client, session_factory, fake_storage = client_context
    _, evidence, job = seed_analysis_job(session_factory)
    plugin_result = seed_plugin_result(session_factory, evidence, job, bucket="evidence")

    response = client.get(f"/api/v1/plugin-results/{plugin_result.id}/raw-output/download")

    assert response.status_code == 400
    assert response.json()["detail"] == "raw plugin output metadata is invalid"
    assert fake_storage.requests == []


def test_plugin_raw_output_download_returns_404_when_object_missing(client_context) -> None:
    client, session_factory, fake_storage = client_context
    _, evidence, job = seed_analysis_job(session_factory)
    plugin_result = seed_plugin_result(session_factory, evidence, job)

    response = client.get(f"/api/v1/plugin-results/{plugin_result.id}/raw-output/download")

    assert response.status_code == 404
    assert response.json()["detail"] == "Raw plugin output is not available for this plugin result."
    assert fake_storage.requests == [("raw-outputs", plugin_result.raw_output_key)]
