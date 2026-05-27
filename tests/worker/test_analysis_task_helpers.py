# Worker analysis task helper tests.

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import create_engine, insert, select, update

from app.db.tables import analysis_jobs, metadata, plugin_results
from app.parsers.persistence import update_plugin_result_parse_error
from app.tasks import status as task_status
from app.tasks.analysis import (
    STATUS_COMPLETED,
    STATUS_QUEUED,
    claim_queued_job,
    evidence_download_path,
    insert_plugin_result,
)
from app.utils.workspace import isolated_job_workspace
from app.volatility.runner import VolatilityRunResult


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


def test_insert_plugin_result_preserves_yara_visibility_metadata() -> None:
    engine = create_engine("sqlite://")
    metadata.create_all(engine, tables=[plugin_results])
    now = datetime.now(timezone.utc)
    run_result = VolatilityRunResult(
        plugin_name="windows.vadyarascan",
        source_plugin="windows.vadyarascan",
        status=task_status.STATUS_SKIPPED,
        raw_output_path="windows_vadyarascan.json",
        command=[],
        return_code=None,
        stdout="",
        stderr="",
        error_message="YARA rule configuration is required for this plugin",
        duration_ms=0,
        extra_data={
            "requires_yara_rules": True,
            "yara_rules_configured": False,
            "skip_reason": "YARA rule configuration is required for this plugin",
        },
    )
    context = {
        "job_id": uuid4(),
        "evidence_id": uuid4(),
        "job_os_family": "windows",
        "plugin_profile": "windows_memory_yara",
    }

    with engine.begin() as conn:
        plugin_result_id = insert_plugin_result(
            conn,
            context,
            run_result,
            raw_output=None,
            started_at=now,
            completed_at=now,
            status=task_status.STATUS_SKIPPED,
            error_message=run_result.error_message,
        )
        stored = conn.execute(select(plugin_results).where(plugin_results.c.id == plugin_result_id)).mappings().one()

    assert stored["extra_data"]["requires_yara_rules"] is True
    assert stored["extra_data"]["yara_rules_configured"] is False


def test_parse_error_keeps_record_count_unknown() -> None:
    engine = create_engine("sqlite://")
    metadata.create_all(engine, tables=[plugin_results])
    now = datetime.now(timezone.utc)
    run_result = VolatilityRunResult(
        plugin_name="windows.vadyarascan",
        source_plugin="windows.vadyarascan",
        status=task_status.STATUS_COMPLETED,
        raw_output_path="windows_vadyarascan.json",
        command=[],
        return_code=0,
        stdout="",
        stderr="",
        error_message=None,
        duration_ms=10,
    )
    context = {
        "job_id": uuid4(),
        "evidence_id": uuid4(),
        "job_os_family": "windows",
        "plugin_profile": "windows_memory_yara",
    }

    with engine.begin() as conn:
        plugin_result_id = insert_plugin_result(
            conn,
            context,
            run_result,
            raw_output=None,
            started_at=now,
            completed_at=now,
            status=task_status.STATUS_COMPLETED,
            error_message=None,
        )
        update_plugin_result_parse_error(conn, plugin_result_id, None, "yara_matches persistence failed: DataError")
        stored = conn.execute(select(plugin_results).where(plugin_results.c.id == plugin_result_id)).mappings().one()

    assert stored["parsed_record_count"] is None
    assert stored["error_message"] == "parse error: yara_matches persistence failed: DataError"
