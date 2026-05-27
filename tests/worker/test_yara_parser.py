# YARA parser tests.

from pathlib import Path

from app.parsers.yara import parse_yara_matches
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


def test_vadyarascan_parser_preserves_process_memory_context() -> None:
    batch = parse_yara_matches(
        [
            {
                "Rule": "RAMSight_Demo_Injection_API_Cluster",
                "Namespace": "default",
                "Tags": ["memory"],
                "PID": 2924,
                "Offset": "0x401000",
                "Value": "VirtualAlloc VirtualProtect",
            }
        ],
        "windows.vadyarascan",
    )
    record = batch.records[0]

    assert record["rule_name"] == "RAMSight_Demo_Injection_API_Cluster"
    assert record["target_type"] == "process_memory"
    assert record["target_identifier"] == "2924"
    assert record["offset"] == 0x401000
