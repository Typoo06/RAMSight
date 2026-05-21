# Module parser tests.

from pathlib import Path

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

