# YARA match parsers.

from app.parsers.common import ParsedArtifactBatch, first_value, is_placeholder_value, normalize_record, to_int, to_str, truncate_text

SIGNED_BIGINT_MIN = -(2**63)
SIGNED_BIGINT_MAX = 2**63 - 1


def tags_from_value(value) -> list[str] | None:
    if is_placeholder_value(value):
        return None
    if isinstance(value, list):
        return [str(item) for item in value]
    return [tag.strip() for tag in str(value).split(",") if tag.strip()]


def offset_value(value) -> tuple[int | None, object | None, str | None]:
    if is_placeholder_value(value):
        return None, None, None
    parsed = to_int(value)
    if parsed is None:
        return None, value, "offset is not numeric"
    if parsed < SIGNED_BIGINT_MIN or parsed > SIGNED_BIGINT_MAX:
        return None, value, "offset is outside signed BIGINT range"
    return parsed, value, None


def parse_yara_matches(rows: list[dict], source_plugin: str) -> ParsedArtifactBatch:
    records = []
    for row in rows:
        raw_record = row
        row = normalize_record(row)
        rule_name = to_str(first_value(row, ["rule", "rule_name", "name"]))
        if not rule_name:
            continue
        target_type = to_str(first_value(row, ["target_type", "layer", "type"]))
        if not target_type and source_plugin in {"windows.vadyarascan", "linux.vmayarascan"}:
            target_type = "process_memory"
        raw_offset = first_value(row, ["offset", "address"])
        parsed_offset, offset_raw, offset_error = offset_value(raw_offset)
        extra_data = dict(raw_record)
        if offset_raw is not None:
            extra_data["offset_raw"] = offset_raw
        if offset_error:
            extra_data["offset_parse_error"] = offset_error
        records.append(
            {
                "rule_name": rule_name,
                "namespace": to_str(first_value(row, ["namespace"])),
                "tags": tags_from_value(first_value(row, ["tags"])),
                "target_type": target_type,
                "target_identifier": to_str(first_value(row, ["target", "owner", "process", "pid", "process_id", "target_identifier"])),
                "offset": parsed_offset,
                "matched_text_excerpt": truncate_text(first_value(row, ["matched_text", "value", "hex"]), limit=1000),
                "extra_data": extra_data,
            }
        )
    return ParsedArtifactBatch("yara_matches", records)
