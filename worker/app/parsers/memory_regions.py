# Memory region artifact parsers.

from app.parsers.common import ParsedArtifactBatch, first_value, to_int, to_str, truncate_text


def is_executable_protection(value: str | None) -> bool:
    return bool(value and "EXECUTE" in value.upper())


def parse_memory_region_artifacts(rows: list[dict], source_plugin: str) -> ParsedArtifactBatch:
    records = []
    for row in rows:
        protection = to_str(first_value(row, ["protection", "protect", "protection_string"]))
        records.append(
            {
                "pid": to_int(first_value(row, ["pid", "PID"])),
                "process_name": to_str(first_value(row, ["process", "process_name", "name"])),
                "start_address": to_str(first_value(row, ["start", "start_address", "vad_start", "offset"])),
                "end_address": to_str(first_value(row, ["end", "end_address", "vad_end"])),
                "protection": protection,
                "is_executable": is_executable_protection(protection),
                "is_private": bool(first_value(row, ["private", "is_private"])),
                "description": truncate_text(first_value(row, ["description", "detail", "notes"])),
                "hexdump_excerpt": truncate_text(first_value(row, ["hexdump", "hex_dump"])),
                "disassembly_excerpt": truncate_text(first_value(row, ["disasm", "disassembly"])),
                "raw_record": row,
            }
        )
    return ParsedArtifactBatch("memory_region_artifacts", records)
