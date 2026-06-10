# Parser registry tests.

from pathlib import Path

from app.parsers.registry import get_parser, parse_raw_output_file, parse_raw_wrapper

FIXTURES = Path(__file__).parent / "fixtures" / "volatility"


def test_registry_dispatches_known_parser() -> None:
    assert get_parser("windows.pslist") is not None
    assert get_parser("windows.vadyarascan") is not None
    assert get_parser("windows.pslist.PsList") is None
    assert get_parser("unknown.plugin") is None


def test_parse_raw_wrapper_dispatches_process_fixture() -> None:
    batch = parse_raw_wrapper(FIXTURES / "windows_pslist_wrapper.json")

    assert batch.table_name == "process_artifacts"
    assert batch.records[0]["pid"] == 4


def test_handles_parser_preserves_no_artifacts_for_mvp() -> None:
    batch = parse_raw_wrapper(FIXTURES / "windows_handles_wrapper.json")

    assert batch.table_name == "module_artifacts"
    assert batch.records == []


def test_parse_raw_output_file_dispatches_by_source_plugin(tmp_path) -> None:
    raw_output = tmp_path / "windows_pslist.json"
    raw_output.write_text(
        '{"columns":["PID","PPID","ImageFileName"],"rows":[[4,0,"System"]]}',
        encoding="utf-8",
    )

    batch = parse_raw_output_file(raw_output, "windows.pslist")

    assert batch.table_name == "process_artifacts"
    assert batch.records[0]["pid"] == 4
