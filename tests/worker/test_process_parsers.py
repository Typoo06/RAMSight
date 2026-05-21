# Process parser tests.

from pathlib import Path

from app.parsers.registry import parse_raw_wrapper

FIXTURES = Path(__file__).parent / "fixtures" / "volatility"


def test_windows_pslist_maps_to_process_artifact() -> None:
    batch = parse_raw_wrapper(FIXTURES / "windows_pslist_wrapper.json")
    record = batch.records[0]

    assert batch.table_name == "process_artifacts"
    assert record["pid"] == 4
    assert record["ppid"] == 0
    assert record["name"] == "System"
    assert record["is_hidden_candidate"] is False
    assert record["raw_record"]["image_file_name"] == "System"

