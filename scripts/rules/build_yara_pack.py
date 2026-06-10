#!/usr/bin/env python3
"""Build explicit RAMSight runtime YARA packs from validated third-party files."""

from __future__ import annotations

import argparse
from pathlib import Path

import yara

from rule_pack_common import (
    PACK_SOURCES,
    REPO_ROOT,
    YARA_ROOT,
    extract_yara_rule_metadata,
    read_json,
    relative_to_repo,
    utc_timestamp,
    write_json,
)


def validation_manifest_path(pack: str) -> Path:
    return YARA_ROOT / "manifests" / f"{pack}.validation.json"


def load_enabled_files(pack: str) -> list[Path]:
    manifest_path = validation_manifest_path(pack)
    if not manifest_path.is_file():
        raise FileNotFoundError(f"validation manifest not found: {relative_to_repo(manifest_path)}")
    manifest = read_json(manifest_path)
    return [REPO_ROOT / path for path in manifest.get("enabled_files", [])]


def compile_text(text: str) -> None:
    yara.compile(source=text)


def pack_header(pack: str) -> str:
    return (
        "/*\n"
        f"  Generated RAMSight runtime YARA pack: {pack}\n"
        "  Source files are preserved unchanged under rules/yara/third_party/.\n"
        "  Do not edit this generated file directly; rebuild it with scripts/rules/build_yara_pack.py.\n"
        "*/\n\n"
    )


def source_pack_for_path(path: Path) -> tuple[str, str]:
    parts = path.parts
    if "elastic" in parts:
        return "elastic_yara", "elastic/protections-artifacts"
    if "neo23x0_signature_base" in parts:
        return "neo23x0_yara", "Neo23x0/signature-base"
    return "unknown", "unknown"


def metadata_for_file(path: Path) -> dict[str, dict]:
    source_pack, source_repository = source_pack_for_path(path)
    rule_metadata = {}
    for rule_name, metadata in extract_yara_rule_metadata(path).items():
        family = metadata.get("malware") or metadata.get("family") or metadata.get("malware_family")
        category = metadata.get("category") or metadata.get("threat_name") or metadata.get("description")
        rule_metadata[rule_name] = {
            "source_pack": source_pack,
            "source_repository": source_repository,
            "source_path": relative_to_repo(path),
            "rule_category": category,
            "malware_family": family,
            "license": metadata.get("license"),
            "author": metadata.get("author"),
            "description": metadata.get("description"),
        }
    return rule_metadata


def build_pack(pack: str, max_files: int | None = None) -> dict:
    if pack not in PACK_SOURCES:
        raise ValueError(f"unknown YARA pack: {pack}")
    enabled_files = load_enabled_files(pack)
    if max_files is not None:
        enabled_files = enabled_files[:max_files]
    if not enabled_files:
        raise ValueError(f"no enabled YARA files are available for pack: {pack}")

    output_path = YARA_ROOT / "compiled" / f"{pack}.yar"
    output_manifest_path = YARA_ROOT / "compiled" / f"{pack}.manifest.json"
    active_sections = []
    skipped = []
    rule_metadata = {}
    sections = [pack_header(pack)]
    seen_rule_names: set[str] = set()

    for path in enabled_files:
        if not path.is_file():
            skipped.append({"path": str(path), "error": "enabled file is missing"})
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        file_metadata = metadata_for_file(path)
        duplicate_names = sorted(rule_name for rule_name in file_metadata if rule_name.lower() in seen_rule_names)
        if duplicate_names:
            skipped.append(
                {
                    "path": relative_to_repo(path),
                    "error": f"duplicate rule names already included in pack: {', '.join(duplicate_names[:10])}",
                }
            )
            continue
        candidate_section = f"\n/* BEGIN {relative_to_repo(path)} */\n{text}\n/* END {relative_to_repo(path)} */\n"
        sections.append(candidate_section)
        active_sections.append(relative_to_repo(path))
        rule_metadata.update(file_metadata)
        seen_rule_names.update(rule_name.lower() for rule_name in file_metadata)

    if not active_sections:
        raise ValueError(f"all enabled files failed combined pack build for pack: {pack}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    active_text = "".join(sections)
    try:
        compile_text(active_text)
    except Exception as exc:  # noqa: BLE001 - final pack error is recorded clearly for the operator.
        raise ValueError(f"combined YARA pack failed final compilation after duplicate filtering: {exc}") from exc
    output_path.write_text(active_text, encoding="utf-8")

    manifest = {
        "pack": pack,
        "source_packs": list(PACK_SOURCES[pack]),
        "built_at": utc_timestamp(),
        "compiled_path": relative_to_repo(output_path),
        "source_file_count": len(active_sections),
        "skipped_file_count": len(skipped),
        "source_files": active_sections,
        "skipped_files": skipped,
        "rules": rule_metadata,
    }
    write_json(output_manifest_path, manifest)
    write_json(YARA_ROOT / "manifests" / f"{pack}.build.json", manifest)
    return manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack", choices=sorted(PACK_SOURCES), required=True)
    parser.add_argument("--max-files", type=int, default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest = build_pack(args.pack, max_files=args.max_files)
    print(f"{args.pack}: built {manifest['compiled_path']}")
    print(f"  source files: {manifest['source_file_count']}")
    print(f"  skipped files: {manifest['skipped_file_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
