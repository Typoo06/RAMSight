# Database and storage integration for HTML report generation.

from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

from sqlalchemy import and_, insert, select, update
from sqlalchemy.engine import Connection

from app.db.tables import (
    analysis_jobs,
    analyst_notes,
    cases,
    command_artifacts,
    evidences,
    iocs,
    memory_region_artifacts,
    module_artifacts,
    network_artifacts,
    plugin_results,
    process_artifacts,
    reports,
    risk_findings,
    yara_matches,
)
from app.reports.context import build_report_context
from app.reports.render import write_technical_report
from app.storage.client import ObjectStorageClient, StorageObject

REPORT_TYPE_TECHNICAL = "technical"
REPORT_FORMAT_HTML = "html"
TECHNICAL_REPORT_FILENAME = "technical_report.html"

ARTIFACT_TABLES = {
    "process_artifacts": process_artifacts,
    "network_artifacts": network_artifacts,
    "module_artifacts": module_artifacts,
    "memory_region_artifacts": memory_region_artifacts,
    "command_artifacts": command_artifacts,
    "yara_matches": yara_matches,
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def fetch_one(conn: Connection, table, row_id: UUID) -> dict:
    row = conn.execute(select(table).where(table.c.id == row_id)).mappings().one_or_none()
    if row is None:
        raise ValueError(f"required report row missing: {table.name}")
    return dict(row)


def load_report_data(conn: Connection, analysis_job_id: UUID, generated_at: datetime | None = None) -> dict:
    analysis_job = fetch_one(conn, analysis_jobs, analysis_job_id)
    case = fetch_one(conn, cases, analysis_job["case_id"])
    evidence = fetch_one(conn, evidences, analysis_job["evidence_id"])
    plugins = conn.execute(select(plugin_results).where(plugin_results.c.analysis_job_id == analysis_job_id)).mappings().all()
    findings = conn.execute(select(risk_findings).where(risk_findings.c.analysis_job_id == analysis_job_id)).mappings().all()
    ioc_rows = conn.execute(select(iocs).where(iocs.c.analysis_job_id == analysis_job_id)).mappings().all()
    note_rows = conn.execute(
        select(analyst_notes).where(
            (analyst_notes.c.analysis_job_id == analysis_job_id) | (analyst_notes.c.case_id == analysis_job["case_id"])
        )
    ).mappings().all()
    artifacts = {}
    for table_name, table in ARTIFACT_TABLES.items():
        rows = conn.execute(select(table).where(table.c.analysis_job_id == analysis_job_id)).mappings().all()
        artifacts[table_name] = [dict(row) for row in rows]
    return build_report_context(
        case=case,
        evidence=evidence,
        analysis_job=analysis_job,
        plugin_results=[dict(row) for row in plugins],
        artifacts=artifacts,
        risk_findings=[dict(row) for row in findings],
        iocs=[dict(row) for row in ioc_rows],
        analyst_notes=[dict(row) for row in note_rows],
        generated_at=generated_at,
    )


def upsert_report_metadata(
    conn: Connection,
    report_context: dict,
    storage_object: StorageObject,
    generated_at: datetime,
) -> UUID:
    analysis_job = report_context["analysis_job"]
    existing_id = conn.execute(
        select(reports.c.id).where(
            and_(
                reports.c.analysis_job_id == analysis_job["id"],
                reports.c.report_type == REPORT_TYPE_TECHNICAL,
                reports.c.format == REPORT_FORMAT_HTML,
            )
        )
    ).scalar_one_or_none()
    values = {
        "case_id": report_context["case"]["id"],
        "evidence_id": report_context["evidence"]["id"],
        "analysis_job_id": analysis_job["id"],
        "os_family": analysis_job.get("os_family") or report_context["evidence"].get("os_family") or "unknown",
        "report_type": REPORT_TYPE_TECHNICAL,
        "format": REPORT_FORMAT_HTML,
        "storage_bucket": storage_object.bucket,
        "storage_key": storage_object.key,
        "generated_at": generated_at,
        "updated_at": generated_at,
    }
    if existing_id is not None:
        conn.execute(update(reports).where(reports.c.id == existing_id).values(**values))
        return existing_id

    report_id = uuid4()
    conn.execute(insert(reports).values(id=report_id, created_at=generated_at, **values))
    return report_id


def run_html_report_generation_for_job(
    conn: Connection,
    analysis_job_id: UUID,
    workspace: Path,
    storage_client: ObjectStorageClient,
    templates_dir: str | Path,
) -> dict:
    generated_at = utc_now()
    report_context = load_report_data(conn, analysis_job_id, generated_at=generated_at)
    report_path = workspace / "reports" / TECHNICAL_REPORT_FILENAME
    write_technical_report(report_path, report_context, templates_dir)
    storage_object = storage_client.upload_report(
        report_context["case"]["id"], analysis_job_id, TECHNICAL_REPORT_FILENAME, report_path, "text/html"
    )
    report_id = upsert_report_metadata(conn, report_context, storage_object, generated_at)
    return {"report_id": report_id, "storage_bucket": storage_object.bucket, "storage_key": storage_object.key}
