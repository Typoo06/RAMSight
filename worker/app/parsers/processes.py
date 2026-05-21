# Process artifact parsers.

from app.parsers.common import ParsedArtifactBatch, first_value, to_datetime, to_int, to_str


def parse_process_artifacts(rows: list[dict], source_plugin: str) -> ParsedArtifactBatch:
    records = []
    for row in rows:
        records.append(
            {
                "pid": to_int(first_value(row, ["pid", "PID"])),
                "ppid": to_int(first_value(row, ["ppid", "PPID", "inherited_from_unique_process_id", "parent_pid"])),
                "name": to_str(first_value(row, ["image_file_name", "name", "process", "comm"])),
                "image_path": to_str(first_value(row, ["image_path", "path", "file_output"])),
                "command_line": to_str(first_value(row, ["command_line", "cmdline", "args"])),
                "user_name": to_str(first_value(row, ["user_name", "user", "owner"])),
                "session_id": to_int(first_value(row, ["session_id", "session"])),
                "created_time": to_datetime(first_value(row, ["create_time", "created_time", "created"])),
                "exited_time": to_datetime(first_value(row, ["exit_time", "exited_time", "exited"])),
                "is_hidden_candidate": source_plugin == "windows.psscan",
                "raw_record": row,
            }
        )
    return ParsedArtifactBatch("process_artifacts", records)

