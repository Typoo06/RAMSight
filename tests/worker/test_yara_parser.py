# YARA parser tests.

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from sqlalchemy import BigInteger, create_engine, select

from app.db.tables import metadata, yara_matches
from app.parsers.common import ParsedArtifactBatch
from app.parsers.persistence import insert_artifact_batch
from app.parsers.registry import parse_raw_wrapper
from app.parsers.yara import parse_yara_matches

FIXTURES = Path(__file__).parent / "fixtures" / "volatility"


def test_yarascan_maps_to_yara_match() -> None:
    batch = parse_raw_wrapper(FIXTURES / "yarascan_wrapper.json")
    record = batch.records[0]

    assert batch.table_name == "yara_matches"
    assert record["rule_name"] == "SuspiciousRule"
    assert record["namespace"] == "default"
    assert record["tags"] == ["memory"]
    assert record["offset"] == 0x400123
    assert record["extra_data"]["offset_raw"] == "0x400123"
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
    assert record["extra_data"]["offset_raw"] == "0x401000"


def test_yara_parser_preserves_large_decimal_offset() -> None:
    large_offset = 5_368_709_120
    batch = parse_yara_matches([{"Rule": "LargeOffset", "Offset": str(large_offset)}], "windows.vadyarascan")
    record = batch.records[0]

    assert record["offset"] == large_offset
    assert record["extra_data"]["offset_raw"] == str(large_offset)


def test_yara_parser_preserves_large_hex_offset() -> None:
    batch = parse_yara_matches([{"Rule": "LargeHexOffset", "Address": "0x7ffdf0001000"}], "windows.vadyarascan")
    record = batch.records[0]

    assert record["offset"] == 0x7FFDF0001000
    assert record["extra_data"]["offset_raw"] == "0x7ffdf0001000"


def test_yara_parser_preserves_non_numeric_offset_without_column_value() -> None:
    batch = parse_yara_matches([{"Rule": "TextOffset", "Offset": "section+0x40"}], "windows.vadyarascan")
    record = batch.records[0]

    assert record["offset"] is None
    assert record["extra_data"]["offset_raw"] == "section+0x40"
    assert record["extra_data"]["offset_parse_error"] == "offset is not numeric"


def test_yara_parser_preserves_too_large_offset_without_column_value() -> None:
    too_large = str(2**63)
    batch = parse_yara_matches([{"Rule": "TooLargeOffset", "Offset": too_large}], "windows.vadyarascan")
    record = batch.records[0]

    assert record["offset"] is None
    assert record["extra_data"]["offset_raw"] == too_large
    assert record["extra_data"]["offset_parse_error"] == "offset is outside signed BIGINT range"


def test_worker_yara_match_offset_uses_big_integer() -> None:
    assert isinstance(yara_matches.c.offset.type, BigInteger)


def test_yara_match_persistence_accepts_large_offset() -> None:
    engine = create_engine("sqlite://")
    metadata.create_all(engine, tables=[yara_matches])
    large_offset = 0x7FFDF0001000
    batch = ParsedArtifactBatch(
        "yara_matches",
        [
            {
                "rule_name": "LargeOffset",
                "namespace": "default",
                "tags": ["memory"],
                "target_type": "process_memory",
                "target_identifier": "2924",
                "offset": large_offset,
                "matched_text_excerpt": "candidate",
                "extra_data": {"offset_raw": "0x7ffdf0001000"},
            }
        ],
    )
    context = {
        "job_id": uuid4(),
        "evidence_id": uuid4(),
        "job_os_family": "windows",
        "source_plugin": "windows.vadyarascan",
    }

    with engine.begin() as conn:
        count = insert_artifact_batch(conn, batch, context, uuid4(), now=datetime.now(timezone.utc))
        stored_offset = conn.execute(select(yara_matches.c.offset)).scalar_one()

    assert count == 1
    assert stored_offset == large_offset
