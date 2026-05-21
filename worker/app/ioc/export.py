# IOC JSON and CSV export helpers.

import csv
import json
from dataclasses import asdict
from pathlib import Path

from app.ioc.types import IOCRecordDraft

CSV_HEADERS = [
    "id",
    "analysis_job_id",
    "evidence_id",
    "risk_finding_id",
    "os_family",
    "source_plugin",
    "ioc_type",
    "value",
    "normalized_value",
    "context",
    "confidence",
    "extra_data",
]


def ioc_to_export_dict(ioc: IOCRecordDraft) -> dict:
    payload = asdict(ioc)
    for key in ("id", "analysis_job_id", "evidence_id", "risk_finding_id"):
        if payload.get(key) is not None:
            payload[key] = str(payload[key])
    return payload


def write_ioc_json_export(path: Path, iocs: list[IOCRecordDraft]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    items = [ioc_to_export_dict(ioc) for ioc in iocs]
    path.write_text(json.dumps({"items": items}, indent=2, sort_keys=True, default=str), encoding="utf-8")


def write_ioc_csv_export(path: Path, iocs: list[IOCRecordDraft]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=CSV_HEADERS)
        writer.writeheader()
        for ioc in iocs:
            row = ioc_to_export_dict(ioc)
            row["extra_data"] = json.dumps(row.get("extra_data") or {}, sort_keys=True, default=str)
            writer.writerow({header: row.get(header) for header in CSV_HEADERS})
