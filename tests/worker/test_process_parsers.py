# Process parser tests.

from pathlib import Path

from app.parsers.processes import parse_process_artifacts
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


def test_process_parser_skips_file_output_placeholder_as_image_path() -> None:
    batch = parse_process_artifacts(
        [{"PID": 2924, "ImageFileName": "WinRAR.exe", "File output": "Disabled"}],
        "windows.pslist",
    )

    assert batch.records[0]["name"] == "WinRAR.exe"
    assert batch.records[0]["image_path"] is None
    assert batch.records[0]["raw_record"]["PID"] == 2924


def test_process_parser_accepts_valid_windows_image_path() -> None:
    batch = parse_process_artifacts(
        [{"PID": 2924, "ImageFileName": "WinRAR.exe", "ImagePath": "C:\\Users\\lab\\Downloads\\WinRAR.exe"}],
        "windows.pslist",
    )

    assert batch.records[0]["image_path"] == "C:\\Users\\lab\\Downloads\\WinRAR.exe"
