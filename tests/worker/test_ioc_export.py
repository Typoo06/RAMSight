# IOC export tests.

import csv
import json
from uuid import uuid4

from app.ioc.export import CSV_HEADERS, write_ioc_csv_export, write_ioc_json_export
from app.ioc.types import IOC_IP_ADDRESS, IOCRecordDraft
from app.storage.keys import ioc_export_key


def sample_ioc() -> IOCRecordDraft:
    return IOCRecordDraft(
        analysis_job_id=uuid4(),
        evidence_id=uuid4(),
        risk_finding_id=uuid4(),
        os_family="windows",
        source_plugin="windows.netscan",
        ioc_type=IOC_IP_ADDRESS,
        value="8.8.8.8",
        normalized_value="8.8.8.8",
        context="public remote address",
        confidence=70,
        extra_data={"severity": "medium", "remote_port": 443},
    )


def test_json_export_formatting(tmp_path) -> None:
    path = tmp_path / "ioc_export.json"
    ioc = sample_ioc()

    write_ioc_json_export(path, [ioc])
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert list(payload) == ["items"]
    assert payload["items"][0]["ioc_type"] == IOC_IP_ADDRESS
    assert payload["items"][0]["extra_data"]["severity"] == "medium"


def test_csv_export_formatting(tmp_path) -> None:
    path = tmp_path / "ioc_export.csv"
    ioc = sample_ioc()

    write_ioc_csv_export(path, [ioc])

    rows = list(csv.DictReader(path.read_text(encoding="utf-8").splitlines()))

    assert rows[0]["ioc_type"] == IOC_IP_ADDRESS
    assert json.loads(rows[0]["extra_data"])["remote_port"] == 443
    assert list(rows[0]) == CSV_HEADERS


def test_ioc_export_key_format() -> None:
    key = ioc_export_key("case-1", "job-1", "ioc_export.json")

    assert key == "case-case-1/job-job-1/iocs/ioc_export.json"
