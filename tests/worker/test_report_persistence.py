# Report storage key and metadata persistence tests.

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import create_engine, select

from app.db.tables import metadata, reports
from app.reports.persistence import upsert_report_metadata
from app.storage.client import StorageObject
from app.storage.keys import report_object_key


def report_context(case_id, evidence_id, job_id) -> dict:
    return {
        "case": {"id": case_id},
        "evidence": {"id": evidence_id, "os_family": "windows"},
        "analysis_job": {"id": job_id, "os_family": "windows"},
    }


def test_report_object_key_generation() -> None:
    assert report_object_key("case-1", "job-1", "technical report.html") == "case-case-1/job-job-1/reports/technical_report.html"


def test_report_metadata_upsert_avoids_duplicates() -> None:
    engine = create_engine("sqlite://")
    metadata.create_all(engine, tables=[reports])
    case_id = uuid4()
    evidence_id = uuid4()
    job_id = uuid4()
    generated_at = datetime(2026, 5, 24, tzinfo=timezone.utc)

    with engine.begin() as conn:
        first_id = upsert_report_metadata(
            conn,
            report_context(case_id, evidence_id, job_id),
            StorageObject("reports", "case-a/job-b/reports/technical_report.html", 100),
            generated_at,
        )
        second_id = upsert_report_metadata(
            conn,
            report_context(case_id, evidence_id, job_id),
            StorageObject("reports", "case-a/job-b/reports/technical_report.html", 120),
            generated_at,
        )
        rows = conn.execute(select(reports)).mappings().all()

    assert first_id == second_id
    assert len(rows) == 1
    assert rows[0]["report_type"] == "technical"
    assert rows[0]["format"] == "html"
