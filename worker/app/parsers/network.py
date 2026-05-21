# Network artifact parsers.

from app.parsers.common import ParsedArtifactBatch, endpoint_parts, first_value, to_datetime, to_int, to_str


def parse_network_artifacts(rows: list[dict], source_plugin: str) -> ParsedArtifactBatch:
    records = []
    for row in rows:
        local_address, local_port = endpoint_parts(first_value(row, ["local_addr", "local", "local_address"]))
        remote_address, remote_port = endpoint_parts(first_value(row, ["foreign_addr", "foreign", "remote_address"]))
        records.append(
            {
                "protocol": to_str(first_value(row, ["proto", "protocol"])),
                "local_address": local_address or to_str(first_value(row, ["local_ip", "local_address"])),
                "local_port": to_int(first_value(row, ["local_port"])) or local_port,
                "remote_address": remote_address or to_str(first_value(row, ["foreign_ip", "remote_ip", "remote_address"])),
                "remote_port": to_int(first_value(row, ["foreign_port", "remote_port"])) or remote_port,
                "state": to_str(first_value(row, ["state"])),
                "pid": to_int(first_value(row, ["pid", "PID"])),
                "process_name": to_str(first_value(row, ["owner", "process", "process_name"])),
                "created_time": to_datetime(first_value(row, ["created", "create_time", "created_time"])),
                "raw_record": row,
            }
        )
    return ParsedArtifactBatch("network_artifacts", records)
