# Module parser tests.

from pathlib import Path

from app.parsers.modules import parse_module_artifacts
from app.parsers.registry import parse_raw_wrapper

FIXTURES = Path(__file__).parent / "fixtures" / "volatility"


def test_windows_dlllist_maps_to_module_artifact() -> None:
    batch = parse_raw_wrapper(FIXTURES / "windows_dlllist_wrapper.json")
    record = batch.records[0]

    assert batch.table_name == "module_artifacts"
    assert record["pid"] == 123
    assert record["process_name"] == "proc.exe"
    assert record["module_name"] == "evil.dll"
    assert record["module_path"] == "C:/Temp/evil.dll"
    assert record["base_address"] == "0x10000000"
    assert record["size_bytes"] == 4096


def test_module_parser_skips_placeholder_module_path() -> None:
    batch = parse_module_artifacts(
        [{"PID": 123, "Process": "proc.exe", "BaseDllName": "missing.dll", "FullDllName": "Disabled"}],
        "windows.dlllist",
    )

    assert batch.records[0]["module_name"] == "missing.dll"
    assert batch.records[0]["module_path"] is None
