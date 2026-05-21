# Tests for object key conventions.

from app.storage.keys import (
    evidence_object_key,
    parsed_plugin_output_key,
    raw_plugin_output_key,
    report_object_key,
)


def test_evidence_object_key_is_os_neutral_and_safe() -> None:
    assert evidence_object_key("case 1", "ev/2", "memory dump.RAW") == "case-case_1/evidence-2/memory_dump.RAW"


def test_raw_plugin_output_key_normalizes_plugin_name() -> None:
    assert raw_plugin_output_key("abc", "job-1", "windows.malfind") == "case-abc/job-job-1/raw/windows_malfind.json"


def test_parsed_plugin_output_key_uses_raw_outputs_layout() -> None:
    assert (
        parsed_plugin_output_key("abc", "job-1", "linux.vmayarascan")
        == "case-abc/job-job-1/parsed/linux_vmayarascan.json"
    )


def test_report_object_key_normalizes_filename() -> None:
    assert report_object_key("abc", "job-1", "technical report.html") == "case-abc/job-job-1/reports/technical_report.html"
