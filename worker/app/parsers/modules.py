# Module artifact parsers.

from app.parsers.common import ParsedArtifactBatch, first_value, normalize_record, os_family_from_source_plugin, to_datetime, to_int, to_path, to_str


def parse_module_artifacts(rows: list[dict], source_plugin: str) -> ParsedArtifactBatch:
    records = []
    os_family = os_family_from_source_plugin(source_plugin)
    for row in rows:
        raw_record = row
        row = normalize_record(row)
        records.append(
            {
                "pid": to_int(first_value(row, ["pid", "PID"])),
                "process_name": to_str(first_value(row, ["process", "process_name", "image_file_name"])),
                "module_name": to_str(first_value(row, ["name", "base_dll_name", "module_name"])),
                "module_path": to_path(first_value(row, ["path", "full_dll_name", "module_path"]), os_family),
                "base_address": to_str(first_value(row, ["base", "base_address"])),
                "size_bytes": to_int(first_value(row, ["size", "size_of_image", "size_bytes"])),
                "load_time": to_datetime(first_value(row, ["load_time", "time_date_stamp"])),
                "raw_record": raw_record,
            }
        )
    return ParsedArtifactBatch("module_artifacts", records)


def parse_handles_as_no_artifacts(rows: list[dict], source_plugin: str) -> ParsedArtifactBatch:
    return ParsedArtifactBatch("module_artifacts", [])
