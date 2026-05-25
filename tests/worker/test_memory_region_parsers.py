# Memory region parser tests.

from pathlib import Path

from app.parsers.memory_regions import parse_memory_region_artifacts
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


def test_malfind_parser_maps_start_end_vpn_aliases() -> None:
    batch = parse_memory_region_artifacts(
        [
            {
                "PID": 1128,
                "Process": "NOTEPAD.exe",
                "Start VPN": 4194304,
                "End VPN": 4198400,
                "Protection": "PAGE_EXECUTE_READWRITE",
                "Private": True,
                "Disasm": "mov eax, eax",
            }
        ],
        "windows.malfind",
    )
    record = batch.records[0]

    assert record["start_address"] == "0x400000"
    assert record["end_address"] == "0x401000"
    assert record["is_executable"] is True
    assert record["is_private"] is True
    assert record["disassembly_excerpt"] == "mov eax, eax"


def test_malfind_parser_extracts_address_range_when_available() -> None:
    batch = parse_memory_region_artifacts(
        [{"PID": 1128, "Process": "NOTEPAD.exe", "Address": "0x500000 - 0x501000", "Protection": "PAGE_EXECUTE_READ"}],
        "windows.malfind",
    )

    assert batch.records[0]["start_address"] == "0x500000"
    assert batch.records[0]["end_address"] == "0x501000"
