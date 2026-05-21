# YARA match parsers.

from app.parsers.common import ParsedArtifactBatch, first_value, to_int, to_str, truncate_text


def tags_from_value(value) -> list[str] | None:
    if value in (None, "", "N/A"):
        return None
    if isinstance(value, list):
        return [str(item) for item in value]
    return [tag.strip() for tag in str(value).split(",") if tag.strip()]


def parse_yara_matches(rows: list[dict], source_plugin: str) -> ParsedArtifactBatch:
    records = []
    for row in rows:
        rule_name = to_str(first_value(row, ["rule", "rule_name", "name"]))
        if not rule_name:
            continue
        records.append(
            {
                "rule_name": rule_name,
                "namespace": to_str(first_value(row, ["namespace"])),
                "tags": tags_from_value(first_value(row, ["tags"])),
                "target_type": to_str(first_value(row, ["target_type", "layer", "type"])),
                "target_identifier": to_str(first_value(row, ["target", "owner", "process", "target_identifier"])),
                "offset": to_int(first_value(row, ["offset", "address"])),
                "matched_text_excerpt": truncate_text(first_value(row, ["matched_text", "value", "hex"]), limit=1000),
                "extra_data": row,
            }
        )
    return ParsedArtifactBatch("yara_matches", records)
