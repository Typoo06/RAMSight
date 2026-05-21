# Worker analysis task helper tests.

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import create_engine, insert, select, update

from app.db.tables import analysis_jobs, metadata
from app.tasks.analysis import (
    STATUS_COMPLETED,
    STATUS_QUEUED,
    claim_queued_job,
    evidence_download_path,
)
from app.utils.workspace import isolated_job_workspace


def test_isolated_job_workspace_cleans_up(tmp_path) -> None:
    job_id = uuid4()

    with isolated_job_workspace(job_id, base_dir=tmp_path) as workspace:
        assert workspace.exists()
        (workspace / "marker.txt").write_text("temporary", encoding="utf-8")

    assert not workspace.exists()


def test_evidence_download_path_removes_source_paths(tmp_path) -> None:
    path = evidence_download_path(tmp_path, "../memory dumps/sample.raw")

    assert path == tmp_path / "evidence" / "evidence.raw"


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
