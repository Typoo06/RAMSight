# Memory region parser tests.

from pathlib import Path

from app.parsers.registry import parse_raw_wrapper

FIXTURES = Path(__file__).parent / "fixtures" / "volatility"


def test_windows_malfind_maps_to_memory_region_artifact() -> None:
    batch = parse_raw_wrapper(FIXTURES / "windows_malfind_wrapper.json")
    record = batch.records[0]

    assert batch.table_name == "memory_region_artifacts"
    assert record["pid"] == 123
    assert record["process_name"] == "proc.exe"
    assert record["start_address"] == "0x400000"
    assert record["end_address"] == "0x401000"
    assert record["is_executable"] is True
    assert record["hexdump_excerpt"] == "4d 5a"

