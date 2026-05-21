# Celery task skeleton for memory analysis jobs.

from dataclasses import dataclass
from datetime import datetime, timezone
import logging
from pathlib import Path, PurePath
from time import perf_counter
from uuid import UUID, uuid4

from sqlalchemy import and_, insert, select, update
from sqlalchemy.engine import Connection

from app.celery_app import celery_app
from app.core.config import get_settings
from app.db.session import engine
from app.db.tables import analysis_jobs, evidences, plugin_results
from app.detection.persistence import insert_detection_stage_error, run_detection_for_job
from app.ioc.persistence import run_ioc_extraction_for_job
from app.parsers.common import ParserError
from app.parsers.persistence import (
    insert_artifact_batch,
    update_plugin_result_parse_error,
    update_plugin_result_parsed_output,
    write_parsed_output,
)
from app.parsers.registry import parse_raw_wrapper
from app.storage.client import ObjectStorageClient, StorageObject
from app.storage.keys import normalize_object_name_part
from app.tasks.status import STATUS_COMPLETED, STATUS_FAILED, STATUS_QUEUED, STATUS_RUNNING
from app.utils.workspace import isolated_job_workspace
from app.volatility.registry import select_plugins
from app.volatility.runner import VolatilityRunResult, ensure_volatility_available, run_volatility_plugin

ANALYSIS_TASK_NAME = "app.tasks.analysis.run_analysis_job"
LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class JobClaimResult:

    claimed: bool
    status: str | None
    reason: str


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def duration_ms_since(started_at: float) -> int:
    return int((perf_counter() - started_at) * 1000)


def short_error_message(exc: BaseException, max_length: int = 500) -> str:
    message = " ".join(str(exc).split()) or exc.__class__.__name__
    return message[:max_length]


# Only queued jobs may be claimed, which prevents duplicate worker execution.
def claim_queued_job(conn: Connection, job_id: UUID, now: datetime | None = None) -> JobClaimResult:
    timestamp = now or utc_now()
    result = conn.execute(
        update(analysis_jobs)
        .where(and_(analysis_jobs.c.id == job_id, analysis_jobs.c.status == STATUS_QUEUED))
        .values(
            status=STATUS_RUNNING,
            started_at=timestamp,
            completed_at=None,
            error_message=None,
            updated_at=timestamp,
        )
    )
    if result.rowcount == 1:
        return JobClaimResult(claimed=True, status=STATUS_RUNNING, reason="claimed")

    current_status = conn.execute(
        select(analysis_jobs.c.status).where(analysis_jobs.c.id == job_id)
    ).scalar_one_or_none()
    if current_status is None:
        return JobClaimResult(claimed=False, status=None, reason="not_found")
    return JobClaimResult(claimed=False, status=current_status, reason=f"not_queued:{current_status}")


def fetch_job_context(conn: Connection, job_id: UUID) -> dict:
    statement = (
        select(
            analysis_jobs.c.id.label("job_id"),
            analysis_jobs.c.case_id,
            analysis_jobs.c.evidence_id,
            analysis_jobs.c.os_family.label("job_os_family"),
            analysis_jobs.c.os_version.label("job_os_version"),
            analysis_jobs.c.architecture.label("job_architecture"),
            analysis_jobs.c.kernel_version.label("job_kernel_version"),
            analysis_jobs.c.symbol_table.label("job_symbol_table"),
            analysis_jobs.c.plugin_profile,
            analysis_jobs.c.requested_plugins,
            evidences.c.original_filename,
            evidences.c.size_bytes.label("evidence_size_bytes"),
            evidences.c.md5,
            evidences.c.sha256,
            evidences.c.storage_bucket,
            evidences.c.storage_key,
            evidences.c.os_family.label("evidence_os_family"),
            evidences.c.os_version.label("evidence_os_version"),
            evidences.c.architecture.label("evidence_architecture"),
            evidences.c.kernel_version.label("evidence_kernel_version"),
            evidences.c.symbol_table.label("evidence_symbol_table"),
            evidences.c.acquisition_tool,
            evidences.c.acquisition_time,
        )
        .select_from(analysis_jobs.join(evidences, analysis_jobs.c.evidence_id == evidences.c.id))
        .where(analysis_jobs.c.id == job_id)
    )
    row = conn.execute(statement).mappings().one_or_none()
    if row is None:
        raise ValueError("analysis job or evidence metadata not found")
    return dict(row)


def validate_evidence_storage_metadata(context: dict) -> None:
    if not context.get("storage_bucket") or not context.get("storage_key"):
        raise ValueError("evidence storage metadata is missing")


# Keep the workspace filename safe even if evidence metadata contains a path.
def evidence_download_path(workspace: Path, original_filename: str | None) -> Path:
    filename = original_filename or "evidence.bin"
    suffix = PurePath(filename).suffix
    safe_name = normalize_object_name_part(f"evidence{suffix or '.bin'}")
    return workspace / "evidence" / safe_name


# Raw stdout/stderr stay in MinIO; PostgreSQL stores status and object metadata only.
def insert_plugin_result(
    conn: Connection,
    context: dict,
    run_result: VolatilityRunResult,
    raw_output: StorageObject | None,
    started_at: datetime,
    completed_at: datetime,
    status: str,
    error_message: str | None,
) -> UUID:
    plugin_result_id = uuid4()
    conn.execute(
        insert(plugin_results).values(
            id=plugin_result_id,
            analysis_job_id=context["job_id"],
            evidence_id=context["evidence_id"],
            os_family=context.get("job_os_family") or context.get("evidence_os_family") or "unknown",
            plugin_profile=context.get("plugin_profile"),
            plugin_name=run_result.plugin_name,
            source_plugin=run_result.source_plugin,
            status=status,
            raw_output_bucket=raw_output.bucket if raw_output else None,
            raw_output_key=raw_output.key if raw_output else None,
            parsed_output_bucket=None,
            parsed_output_key=None,
            parsed_record_count=0,
            error_message=error_message,
            duration_ms=run_result.duration_ms,
            extra_data={"return_code": run_result.return_code, "timed_out": run_result.timed_out},
            started_at=started_at,
            completed_at=completed_at,
            created_at=started_at,
            updated_at=completed_at,
        )
    )
    return plugin_result_id


def mark_job_completed(conn: Connection, job_id: UUID, completed_at: datetime, duration_ms: int) -> None:
    conn.execute(
        update(analysis_jobs)
        .where(analysis_jobs.c.id == job_id)
        .values(
            status=STATUS_COMPLETED,
            completed_at=completed_at,
            duration_ms=duration_ms,
            error_message=None,
            updated_at=completed_at,
        )
    )


def mark_job_failed(conn: Connection, job_id: UUID, error_message: str, completed_at: datetime, duration_ms: int) -> None:
    conn.execute(
        update(analysis_jobs)
        .where(analysis_jobs.c.id == job_id)
        .values(
            status=STATUS_FAILED,
            completed_at=completed_at,
            duration_ms=duration_ms,
            error_message=error_message,
            updated_at=completed_at,
        )
    )


@celery_app.task(name=ANALYSIS_TASK_NAME)
def run_analysis_job(job_id: str) -> dict:
    task_started = perf_counter()
    try:
        parsed_job_id = UUID(str(job_id))
    except ValueError as exc:
        return {"status": STATUS_FAILED, "reason": short_error_message(exc)}

    with engine.begin() as conn:
        claim = claim_queued_job(conn, parsed_job_id)

    if not claim.claimed:
        return {"status": "noop", "job_status": claim.status, "reason": claim.reason}

    try:
        with engine.begin() as conn:
            context = fetch_job_context(conn, parsed_job_id)
        validate_evidence_storage_metadata(context)
        selected_plugins = select_plugins(
            context.get("job_os_family"),
            plugin_profile=context.get("plugin_profile"),
            requested_plugins=context.get("requested_plugins"),
        )
        ensure_volatility_available(get_settings().volatility_path)

        storage_client = ObjectStorageClient()
        with isolated_job_workspace(parsed_job_id) as workspace:
            evidence_path = evidence_download_path(workspace, context.get("original_filename"))
            storage_client.download_file(
                context["storage_bucket"],
                context["storage_key"],
                evidence_path,
            )
            raw_dir = workspace / "raw"
            successful_plugins = 0
            plugin_result_ids = []
            detection_finding_count = 0
            ioc_count = 0
            ioc_export_keys = {}

            for plugin in selected_plugins:
                plugin_started_at = utc_now()
                run_result = run_volatility_plugin(plugin, evidence_path, raw_dir)
                plugin_completed_at = utc_now()
                raw_output = None
                status = run_result.status
                error_message = run_result.error_message
                try:
                    raw_output = storage_client.upload_raw_plugin_output(
                        context["case_id"],
                        parsed_job_id,
                        run_result.plugin_name,
                        run_result.raw_output_path,
                    )
                except Exception as exc:  # noqa: BLE001 - upload failure is stored as plugin metadata.
                    status = STATUS_FAILED
                    error_message = short_error_message(f"raw output upload failed: {exc}")

                with engine.begin() as conn:
                    plugin_result_id = insert_plugin_result(
                        conn,
                        context,
                        run_result,
                        raw_output,
                        plugin_started_at,
                        plugin_completed_at,
                        status,
                        error_message,
                    )
                    plugin_result_ids.append(plugin_result_id)

                if status == STATUS_COMPLETED:
                    parse_context = {**context, "source_plugin": run_result.source_plugin}
                    try:
                        batch = parse_raw_wrapper(run_result.raw_output_path)
                        parsed_path = workspace / "parsed" / run_result.raw_output_path.name
                        parsed_count = len(batch.records)
                        write_parsed_output(parsed_path, batch, parsed_count)
                        parsed_output = storage_client.upload_parsed_output(
                            context["case_id"], parsed_job_id, run_result.plugin_name, parsed_path
                        )
                        with engine.begin() as conn:
                            parsed_count = insert_artifact_batch(
                                conn, batch, parse_context, plugin_result_id, utc_now()
                            )
                            update_plugin_result_parsed_output(
                                conn, plugin_result_id, parsed_output.bucket, parsed_output.key, parsed_count
                            )
                    except (ParserError, Exception) as exc:  # noqa: BLE001 - parser failures stay plugin-local.
                        with engine.begin() as conn:
                            update_plugin_result_parse_error(
                                conn, plugin_result_id, error_message, short_error_message(exc)
                            )
                if status == STATUS_COMPLETED:
                    successful_plugins += 1

            if successful_plugins > 0:
                detection_context = {
                    "analysis_job_id": parsed_job_id,
                    "evidence_id": context["evidence_id"],
                    "os_family": context.get("job_os_family") or context.get("evidence_os_family") or "unknown",
                }
                try:
                    with engine.begin() as conn:
                        detection_finding_count = run_detection_for_job(
                            conn, detection_context, get_settings().rules_dir
                        )
                except Exception as exc:  # noqa: BLE001 - detection errors should not discard analysis artifacts.
                    with engine.begin() as conn:
                        insert_detection_stage_error(conn, detection_context, short_error_message(exc))

                ioc_context = {**detection_context, "case_id": context["case_id"]}
                try:
                    with engine.begin() as conn:
                        ioc_result = run_ioc_extraction_for_job(conn, ioc_context, workspace, storage_client)
                    ioc_count = ioc_result["inserted_count"]
                    ioc_export_keys = {
                        "json": ioc_result["json_export_key"],
                        "csv": ioc_result["csv_export_key"],
                    }
                except Exception as exc:  # noqa: BLE001 - IOC extraction must not fail an otherwise useful job.
                    error_message = short_error_message(exc)
                    LOGGER.warning("IOC extraction failed for job %s: %s", parsed_job_id, error_message)
                    ioc_export_keys = {"error": error_message}

        completed_at = utc_now()
        elapsed_ms = duration_ms_since(task_started)
        with engine.begin() as conn:
            if successful_plugins > 0:
                mark_job_completed(conn, parsed_job_id, completed_at, elapsed_ms)
                job_status = STATUS_COMPLETED
            else:
                mark_job_failed(conn, parsed_job_id, "all selected Volatility plugins failed", completed_at, elapsed_ms)
                job_status = STATUS_FAILED

        return {
            "status": job_status,
            "job_id": str(parsed_job_id),
            "plugin_result_ids": [str(plugin_result_id) for plugin_result_id in plugin_result_ids],
            "successful_plugins": successful_plugins,
            "detection_findings": detection_finding_count,
            "iocs": ioc_count,
            "ioc_exports": ioc_export_keys,
        }
    except Exception as exc:  # noqa: BLE001 - task boundary stores a safe failure summary.
        completed_at = utc_now()
        elapsed_ms = duration_ms_since(task_started)
        error_message = short_error_message(exc)
        with engine.begin() as conn:
            mark_job_failed(conn, parsed_job_id, error_message, completed_at, elapsed_ms)
        return {"status": STATUS_FAILED, "job_id": str(parsed_job_id), "error_message": error_message}
