# Memory region artifact parsers.

import re

from app.parsers.common import ParsedArtifactBatch, first_value, normalize_record, to_bool, to_int, to_str, truncate_text

ADDRESS_RANGE_RE = re.compile(r"(?P<start>0x[0-9a-fA-F]+|\d+)\s*[-:]\s*(?P<end>0x[0-9a-fA-F]+|\d+)")


def is_executable_protection(value: str | None) -> bool:
    return bool(value and "EXECUTE" in value.upper())


def address_to_str(value) -> str | None:
    if isinstance(value, int):
        return hex(value)
    text = to_str(value)
    if text is None:
        return None
    if text.lower().startswith("0x"):
        return text
    if text.isdigit():
        return hex(int(text))
    return text


def address_range_from_row(row: dict) -> tuple[str | None, str | None]:
    for alias in ["address", "range", "memory_range", "vad", "vad_range"]:
        text = to_str(first_value(row, [alias]))
        if not text:
            continue
        match = ADDRESS_RANGE_RE.search(text)
        if match:
            return address_to_str(match.group("start")), address_to_str(match.group("end"))
    return None, None


def parse_memory_region_artifacts(rows: list[dict], source_plugin: str) -> ParsedArtifactBatch:
    records = []
    for row in rows:
        raw_record = row
        row = normalize_record(row)
        protection = to_str(first_value(row, ["protection", "protect", "protection_string"]))
        start_address = address_to_str(
            first_value(row, ["start", "start_address", "vad_start", "start_vpn", "start_va", "virtual_address", "offset"])
        )
        end_address = address_to_str(first_value(row, ["end", "end_address", "vad_end", "end_vpn", "end_va"]))
        if not start_address or not end_address:
            range_start, range_end = address_range_from_row(row)
            start_address = start_address or range_start
            end_address = end_address or range_end
        records.append(
            {
                "pid": to_int(first_value(row, ["pid", "PID"])),
                "process_name": to_str(first_value(row, ["process", "process_name", "name"])),
                "start_address": start_address,
                "end_address": end_address,
                "protection": protection,
                "is_executable": is_executable_protection(protection),
                "is_private": to_bool(first_value(row, ["private", "is_private"])),
                "description": truncate_text(first_value(row, ["description", "detail", "notes"])),
                "hexdump_excerpt": truncate_text(first_value(row, ["hexdump", "hex_dump", "hexdump_excerpt"])),
                "disassembly_excerpt": truncate_text(first_value(row, ["disasm", "disassembly", "disassembly_excerpt"])),
                "raw_record": raw_record,
            }
        )
    return ParsedArtifactBatch("memory_region_artifacts", records)
