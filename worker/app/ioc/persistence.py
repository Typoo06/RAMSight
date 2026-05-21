# Database integration for IOC extraction.

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from sqlalchemy import insert, select
from sqlalchemy.engine import Connection

from app.db.tables import (
    command_artifacts,
    iocs,
    memory_region_artifacts,
    module_artifacts,
    network_artifacts,
    process_artifacts,
    risk_findings,
    yara_matches,
)
from app.ioc.export import write_ioc_csv_export, write_ioc_json_export
from app.ioc.extractor import extract_iocs
from app.ioc.types import IOCRecordDraft
from app.storage.client import ObjectStorageClient

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


def load_artifacts(conn: Connection, analysis_job_id: UUID) -> dict[str, list[dict]]:
    artifacts = {}
    for table_name, table in ARTIFACT_TABLES.items():
        rows = conn.execute(select(table).where(table.c.analysis_job_id == analysis_job_id)).mappings().all()
        artifacts[table_name] = [dict(row) for row in rows]
    return artifacts


def load_risk_findings(conn: Connection, analysis_job_id: UUID) -> list[dict]:
    rows = conn.execute(select(risk_findings).where(risk_findings.c.analysis_job_id == analysis_job_id)).mappings().all()
    return [dict(row) for row in rows]


def ioc_to_row(ioc: IOCRecordDraft, now: datetime) -> dict:
    payload = asdict(ioc)
    payload["created_at"] = now
    payload["updated_at"] = now
    return payload


def insert_iocs(conn: Connection, ioc_records: list[IOCRecordDraft], now: datetime | None = None) -> int:
    if not ioc_records:
        return 0
    timestamp = now or utc_now()
    conn.execute(insert(iocs), [ioc_to_row(ioc, timestamp) for ioc in ioc_records])
    return len(ioc_records)


def run_ioc_extraction_for_job(
    conn: Connection,
    context: dict,
    workspace: Path,
    storage_client: ObjectStorageClient,
) -> dict:
    artifacts = load_artifacts(conn, context["analysis_job_id"])
    findings = load_risk_findings(conn, context["analysis_job_id"])
    extracted = extract_iocs(artifacts, findings, context)
    inserted_count = insert_iocs(conn, extracted)

    export_dir = workspace / "iocs"
    json_path = export_dir / "ioc_export.json"
    csv_path = export_dir / "ioc_export.csv"
    write_ioc_json_export(json_path, extracted)
    write_ioc_csv_export(csv_path, extracted)
    result = {
        "inserted_count": inserted_count,
        "json_export_bucket": None,
        "json_export_key": None,
        "csv_export_bucket": None,
        "csv_export_key": None,
    }
    try:
        json_object = storage_client.upload_ioc_export(
            context["case_id"], context["analysis_job_id"], "ioc_export.json", json_path, "application/json"
        )
        csv_object = storage_client.upload_ioc_export(
            context["case_id"], context["analysis_job_id"], "ioc_export.csv", csv_path, "text/csv"
        )
        result.update(
            {
                "json_export_bucket": json_object.bucket,
                "json_export_key": json_object.key,
                "csv_export_bucket": csv_object.bucket,
                "csv_export_key": csv_object.key,
            }
        )
    except Exception as exc:  # noqa: BLE001 - export failure should not discard IOC database rows.
        result["export_error"] = " ".join(str(exc).split())[:500]
    return result
