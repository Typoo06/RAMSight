# Celery task skeleton for memory analysis jobs.

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path, PurePath
from time import perf_counter
from uuid import UUID, uuid4

from sqlalchemy import and_, insert, select, update
from sqlalchemy.engine import Connection

from app.celery_app import celery_app
from app.db.session import engine
from app.db.tables import analysis_jobs, evidences, plugin_results
from app.storage.client import ObjectStorageClient, StorageObject
from app.storage.keys import normalize_object_name_part
from app.utils.workspace import isolated_job_workspace

ANALYSIS_TASK_NAME = "app.tasks.analysis.run_analysis_job"
PLACEHOLDER_PLUGIN_NAME = "analysis.placeholder"
STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"


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


# Placeholder output is OS-neutral so Linux support can reuse the same pipeline shape.
def create_placeholder_raw_output(
    output_path: Path,
    context: dict,
    downloaded_evidence: StorageObject,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "plugin_name": PLACEHOLDER_PLUGIN_NAME,
        "source_plugin": PLACEHOLDER_PLUGIN_NAME,
        "status": STATUS_COMPLETED,
        "placeholder": True,
        "generated_at": utc_now().isoformat(),
        "message": "Placeholder analysis completed; real Volatility execution is not implemented yet.",
        "job": {
            "id": str(context["job_id"]),
            "case_id": str(context["case_id"]),
            "evidence_id": str(context["evidence_id"]),
            "os_family": context.get("job_os_family"),
            "os_version": context.get("job_os_version"),
            "architecture": context.get("job_architecture"),
            "kernel_version": context.get("job_kernel_version"),
            "symbol_table": context.get("job_symbol_table"),
            "plugin_profile": context.get("plugin_profile"),
            "requested_plugins": context.get("requested_plugins"),
        },
        "evidence": {
            "original_filename": context.get("original_filename"),
            "size_bytes": context.get("evidence_size_bytes"),
            "md5": context.get("md5"),
            "sha256": context.get("sha256"),
            "storage_bucket": context.get("storage_bucket"),
            "storage_key": context.get("storage_key"),
            "downloaded_size_bytes": downloaded_evidence.size_bytes,
            "os_family": context.get("evidence_os_family"),
            "os_version": context.get("evidence_os_version"),
            "architecture": context.get("evidence_architecture"),
            "kernel_version": context.get("evidence_kernel_version"),
            "symbol_table": context.get("evidence_symbol_table"),
            "acquisition_tool": context.get("acquisition_tool"),
            "acquisition_time": (
                context["acquisition_time"].isoformat() if context.get("acquisition_time") else None
            ),
        },
    }
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


# One placeholder plugin result preserves the future raw-output contract without parsing yet.
def insert_completed_placeholder_plugin_result(
    conn: Connection,
    context: dict,
    raw_output: StorageObject,
    started_at: datetime,
    completed_at: datetime,
    duration_ms: int,
) -> UUID:
    plugin_result_id = uuid4()
    conn.execute(
        insert(plugin_results).values(
            id=plugin_result_id,
            analysis_job_id=context["job_id"],
            evidence_id=context["evidence_id"],
            os_family=context.get("job_os_family") or context.get("evidence_os_family") or "unknown",
            plugin_profile=context.get("plugin_profile"),
            plugin_name=PLACEHOLDER_PLUGIN_NAME,
            source_plugin=PLACEHOLDER_PLUGIN_NAME,
            status=STATUS_COMPLETED,
            raw_output_bucket=raw_output.bucket,
            raw_output_key=raw_output.key,
            parsed_output_bucket=None,
            parsed_output_key=None,
            parsed_record_count=0,
            error_message=None,
            duration_ms=duration_ms,
            extra_data={"placeholder": True},
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

    plugin_started_at = utc_now()
    try:
        with engine.begin() as conn:
            context = fetch_job_context(conn, parsed_job_id)
        validate_evidence_storage_metadata(context)

        storage_client = ObjectStorageClient()
        with isolated_job_workspace(parsed_job_id) as workspace:
            evidence_path = evidence_download_path(workspace, context.get("original_filename"))
            downloaded_evidence = storage_client.download_file(
                context["storage_bucket"],
                context["storage_key"],
                evidence_path,
            )
            raw_output_path = workspace / "raw" / f"{PLACEHOLDER_PLUGIN_NAME}.json"
            create_placeholder_raw_output(raw_output_path, context, downloaded_evidence)
            uploaded_raw_output = storage_client.upload_raw_plugin_output(
                context["case_id"],
                parsed_job_id,
                PLACEHOLDER_PLUGIN_NAME,
                raw_output_path,
            )

        completed_at = utc_now()
        elapsed_ms = duration_ms_since(task_started)
        with engine.begin() as conn:
            plugin_result_id = insert_completed_placeholder_plugin_result(
                conn,
                context,
                uploaded_raw_output,
                plugin_started_at,
                completed_at,
                elapsed_ms,
            )
            mark_job_completed(conn, parsed_job_id, completed_at, elapsed_ms)

        return {
            "status": STATUS_COMPLETED,
            "job_id": str(parsed_job_id),
            "plugin_result_id": str(plugin_result_id),
            "raw_output_bucket": uploaded_raw_output.bucket,
            "raw_output_key": uploaded_raw_output.key,
        }
    except Exception as exc:  # noqa: BLE001 - task boundary stores a safe failure summary.
        completed_at = utc_now()
        elapsed_ms = duration_ms_since(task_started)
        error_message = short_error_message(exc)
        with engine.begin() as conn:
            mark_job_failed(conn, parsed_job_id, error_message, completed_at, elapsed_ms)
        return {"status": STATUS_FAILED, "job_id": str(parsed_job_id), "error_message": error_message}
