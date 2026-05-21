# Worker analysis task helper tests.

import json
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import create_engine, insert, select, update

from app.db.tables import analysis_jobs, metadata
from app.storage.client import StorageObject
from app.tasks.analysis import (
    PLACEHOLDER_PLUGIN_NAME,
    STATUS_COMPLETED,
    STATUS_QUEUED,
    claim_queued_job,
    create_placeholder_raw_output,
)
from app.utils.workspace import isolated_job_workspace


def test_isolated_job_workspace_cleans_up(tmp_path) -> None:
    job_id = uuid4()

    with isolated_job_workspace(job_id, base_dir=tmp_path) as workspace:
        assert workspace.exists()
        (workspace / "marker.txt").write_text("temporary", encoding="utf-8")

    assert not workspace.exists()


def test_create_placeholder_raw_output_is_os_neutral(tmp_path) -> None:
    output_path = tmp_path / "raw" / "placeholder.json"
    job_id = uuid4()
    case_id = uuid4()
    evidence_id = uuid4()

    create_placeholder_raw_output(
        output_path,
        {
            "job_id": job_id,
            "case_id": case_id,
            "evidence_id": evidence_id,
            "job_os_family": "unknown",
            "job_os_version": None,
            "job_architecture": None,
            "job_kernel_version": None,
            "job_symbol_table": None,
            "plugin_profile": "default",
            "requested_plugins": None,
            "original_filename": "sample.raw",
            "evidence_size_bytes": 10,
            "md5": "0" * 32,
            "sha256": "1" * 64,
            "storage_bucket": "evidence",
            "storage_key": "case-a/evidence-b/sample.raw",
            "evidence_os_family": "unknown",
            "evidence_os_version": None,
            "evidence_architecture": None,
            "evidence_kernel_version": None,
            "evidence_symbol_table": None,
            "acquisition_tool": None,
            "acquisition_time": None,
        },
        StorageObject(bucket="evidence", key="case-a/evidence-b/sample.raw", size_bytes=10),
    )

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["plugin_name"] == PLACEHOLDER_PLUGIN_NAME
    assert payload["source_plugin"] == PLACEHOLDER_PLUGIN_NAME
    assert payload["status"] == STATUS_COMPLETED
    assert payload["placeholder"] is True
    assert "windows." not in payload["plugin_name"]
    assert "linux." not in payload["plugin_name"]


def test_claim_queued_job_only_claims_queued_jobs() -> None:
    engine = create_engine("sqlite://")
    metadata.create_all(engine, tables=[analysis_jobs])
    job_id = uuid4()
    now = datetime.now(timezone.utc)

    with engine.begin() as conn:
        conn.execute(
            insert(analysis_jobs).values(
                id=job_id,
                case_id=uuid4(),
                evidence_id=uuid4(),
                status=STATUS_QUEUED,
                os_family="unknown",
                created_at=now,
                updated_at=now,
            )
        )

        first_claim = claim_queued_job(conn, job_id, now=now)
        second_claim = claim_queued_job(conn, job_id, now=now)
        stored_status = conn.execute(select(analysis_jobs.c.status).where(analysis_jobs.c.id == job_id)).scalar_one()

        conn.execute(update(analysis_jobs).where(analysis_jobs.c.id == job_id).values(status=STATUS_COMPLETED))
        completed_claim = claim_queued_job(conn, job_id, now=now)

    assert first_claim.claimed is True
    assert first_claim.status == "running"
    assert second_claim.claimed is False
    assert second_claim.status == "running"
    assert completed_claim.claimed is False
    assert completed_claim.status == STATUS_COMPLETED
    assert stored_status == "running"

