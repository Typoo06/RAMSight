# Command artifact parsers.

from app.parsers.common import ParsedArtifactBatch, first_value, to_int, to_str


def parse_command_artifacts(rows: list[dict], source_plugin: str) -> ParsedArtifactBatch:
    records = []
    for row in rows:
        records.append(
            {
                "pid": to_int(first_value(row, ["pid", "PID"])),
                "process_name": to_str(first_value(row, ["process", "image_file_name", "name"])),
                "command": to_str(first_value(row, ["args", "command_line", "command", "cmdline"])),
                "shell_type": "cmdline" if source_plugin == "windows.cmdline" else None,
                "user_name": to_str(first_value(row, ["user_name", "user", "owner"])),
                "executed_at": None,
                "raw_record": row,
            }
        )
    return ParsedArtifactBatch("command_artifacts", records)

