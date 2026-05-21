# Command parser tests.

from pathlib import Path

from app.parsers.registry import parse_raw_wrapper

FIXTURES = Path(__file__).parent / "fixtures" / "volatility"


def test_windows_cmdline_maps_to_command_artifact() -> None:
    batch = parse_raw_wrapper(FIXTURES / "windows_cmdline_wrapper.json")
    record = batch.records[0]

    assert batch.table_name == "command_artifacts"
    assert record["pid"] == 123
    assert record["process_name"] == "powershell.exe"
    assert record["command"] == "powershell.exe -enc AAAA"
    assert record["shell_type"] == "cmdline"

