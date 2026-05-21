# Network parser tests.

from pathlib import Path

from app.parsers.registry import parse_raw_wrapper

FIXTURES = Path(__file__).parent / "fixtures" / "volatility"


def test_windows_netscan_maps_to_network_artifact() -> None:
    batch = parse_raw_wrapper(FIXTURES / "windows_netscan_wrapper.json")
    record = batch.records[0]

    assert batch.table_name == "network_artifacts"
    assert record["protocol"] == "TCPv4"
    assert record["local_address"] == "127.0.0.1"
    assert record["local_port"] == 4444
    assert record["remote_address"] == "10.0.0.2"
    assert record["remote_port"] == 80
    assert record["pid"] == 123

