# Export helpers for paginated RAMSight result records.

from dataclasses import dataclass
from datetime import date, datetime
import csv
import io
import json
from typing import Iterable
from uuid import UUID


@dataclass(frozen=True)
class ExportFile:
    filename: str
    media_type: str
    content: bytes


def serialize_value(value):
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): serialize_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [serialize_value(item) for item in value]
    return value


def csv_cell_value(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return value


def export_rows(rows: Iterable[object], fields: list[str]) -> list[dict]:
    exported: list[dict] = []
    for row in rows:
        item = {}
        for field in fields:
            item[field] = serialize_value(getattr(row, field, None))
        exported.append(item)
    return exported


def json_export(filename: str, kind: str, rows: list[dict]) -> ExportFile:
    payload = {"kind": kind, "count": len(rows), "items": rows}
    content = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
    return ExportFile(filename=filename, media_type="application/json", content=content)


def csv_export(filename: str, rows: list[dict]) -> ExportFile:
    output = io.StringIO()
    if rows:
        writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()), extrasaction="ignore")
        writer.writeheader()
        writer.writerows([{key: csv_cell_value(value) for key, value in row.items()} for row in rows])
    else:
        output.write("")
    return ExportFile(filename=filename, media_type="text/csv; charset=utf-8", content=output.getvalue().encode("utf-8"))


def build_export_file(filename_base: str, kind: str, rows: list[dict], export_format: str) -> ExportFile:
    normalized_format = export_format.lower()
    if normalized_format == "json":
        return json_export(f"{filename_base}.json", kind, rows)
    if normalized_format == "csv":
        return csv_export(f"{filename_base}.csv", rows)
    raise ValueError("unsupported export format")
