# Persistence helpers for parsed artifacts.

from datetime import datetime
import json
from pathlib import Path
from uuid import uuid4

from sqlalchemy import insert, update
from sqlalchemy.engine import Connection

from app.db.tables import (
    command_artifacts,
    memory_region_artifacts,
    module_artifacts,
    network_artifacts,
    plugin_results,
    process_artifacts,
    yara_matches,
)
from app.parsers.common import ParsedArtifactBatch

ARTIFACT_TABLES = {
    "process_artifacts": process_artifacts,
    "network_artifacts": network_artifacts,
    "module_artifacts": module_artifacts,
    "memory_region_artifacts": memory_region_artifacts,
    "command_artifacts": command_artifacts,
    "yara_matches": yara_matches,
}


def artifact_rows_with_context(batch: ParsedArtifactBatch, context: dict, plugin_result_id, now: datetime) -> list[dict]:
    rows = []
    for record in batch.records:
        row = {
            **record,
            "id": uuid4(),
            "analysis_job_id": context["job_id"],
            "evidence_id": context["evidence_id"],
            "plugin_result_id": plugin_result_id,
            "os_family": context.get("job_os_family") or context.get("evidence_os_family") or "unknown",
            "source_plugin": context["source_plugin"],
            "created_at": now,
        }
        rows.append(row)
    return rows


def insert_artifact_batch(conn: Connection, batch: ParsedArtifactBatch, context: dict, plugin_result_id, now: datetime) -> int:
    if not batch.table_name or not batch.records:
        return 0
    table = ARTIFACT_TABLES[batch.table_name]
    rows = artifact_rows_with_context(batch, context, plugin_result_id, now)
    conn.execute(insert(table), rows)
    return len(rows)


def write_parsed_output(path: Path, batch: ParsedArtifactBatch, record_count: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"table_name": batch.table_name, "record_count": record_count, "records": batch.records}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")


def update_plugin_result_parsed_output(conn: Connection, plugin_result_id, bucket: str, key: str, record_count: int) -> None:
    conn.execute(
        update(plugin_results)
        .where(plugin_results.c.id == plugin_result_id)
        .values(parsed_output_bucket=bucket, parsed_output_key=key, parsed_record_count=record_count)
    )


def update_plugin_result_parse_error(conn: Connection, plugin_result_id, existing_error: str | None, parse_error: str) -> None:
    prefix = f"parse error: {parse_error}"
    message = f"{existing_error}; {prefix}" if existing_error else prefix
    conn.execute(
        update(plugin_results)
        .where(plugin_results.c.id == plugin_result_id)
        .values(error_message=message[:500], parsed_record_count=0)
    )

