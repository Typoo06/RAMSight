# YARA parser tests.

from pathlib import Path

from app.parsers.registry import parse_raw_wrapper

FIXTURES = Path(__file__).parent / "fixtures" / "volatility"


def test_yarascan_maps_to_yara_match() -> None:
    batch = parse_raw_wrapper(FIXTURES / "yarascan_wrapper.json")
    record = batch.records[0]

    assert batch.table_name == "yara_matches"
    assert record["rule_name"] == "SuspiciousRule"
    assert record["namespace"] == "default"
    assert record["tags"] == ["memory"]
    assert record["offset"] == 0x400123
    assert record["matched_text_excerpt"] == "MZ header"

