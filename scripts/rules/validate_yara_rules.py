#!/usr/bin/env python3
"""Validate imported third-party YARA files independently."""

from __future__ import annotations

import argparse
from pathlib import Path
import shutil

import yara

from rule_pack_common import (
    PACK_SOURCES,
    REPO_ROOT,
    SOURCES,
    YARA_ROOT,
    count_yara_rules,
    iter_rule_files,
    relative_to_repo,
    utc_timestamp,
    write_json,
)


def quarantine_path(source_key: str, rule_file: Path, source_root: Path) -> Path:
    relative = rule_file.relative_to(source_root)
    return YARA_ROOT / "disabled" / source_key / relative


def validate_source(source_key: str, copy_disabled: bool = True) -> dict:
    source = SOURCES[source_key]
    rule_files = iter_rule_files(source.import_root, source.rule_extensions)
    disabled_root = YARA_ROOT / "disabled" / source.key
    if copy_disabled and disabled_root.exists():
        shutil.rmtree(disabled_root)

    enabled = []
    disabled = []
    rule_count = 0
    for rule_file in rule_files:
        rule_count += count_yara_rules(rule_file)
        try:
            yara.compile(filepath=str(rule_file))
        except Exception as exc:  # noqa: BLE001 - validation records exact compiler error.
            disabled_entry = {
                "path": relative_to_repo(rule_file),
                "error": str(exc),
                "quarantine_path": relative_to_repo(quarantine_path(source_key, rule_file, source.import_root)),
            }
            disabled.append(disabled_entry)
            if copy_disabled:
                destination = quarantine_path(source_key, rule_file, source.import_root)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(rule_file, destination)
            continue
        enabled.append(relative_to_repo(rule_file))

    manifest = {
        "source_repository": source.source_repository,
        "source_url": source.source_url,
        "license": source.license_name,
        "imported_path": relative_to_repo(source.import_root),
        "runtime_pack": source.runtime_pack,
        "validated_at": utc_timestamp(),
        "rule_file_count": len(rule_files),
        "rule_count": rule_count,
        "enabled_file_count": len(enabled),
        "disabled_file_count": len(disabled),
        "compile_status": "pass" if not disabled else "partial",
        "enabled_files": enabled,
        "disabled_files": disabled,
    }
    write_json(source.manifest_root / f"{source.runtime_pack}.validation.json", manifest)
    return manifest


def build_all_manifest(source_manifests: list[dict]) -> dict:
    enabled = []
    disabled = []
    rule_count = 0
    for manifest in source_manifests:
        enabled.extend(manifest.get("enabled_files") or [])
        disabled.extend(manifest.get("disabled_files") or [])
        rule_count += int(manifest.get("rule_count") or 0)
    combined = {
        "source_repository": "elastic/protections-artifacts + Neo23x0/signature-base",
        "source_url": "multiple",
        "license": "Elastic License 2.0 and Detection Rule License 1.1",
        "imported_path": "rules/yara/third_party",
        "runtime_pack": "third_party_yara_all",
        "validated_at": utc_timestamp(),
        "rule_file_count": len(enabled) + len(disabled),
        "rule_count": rule_count,
        "enabled_file_count": len(enabled),
        "disabled_file_count": len(disabled),
        "compile_status": "pass" if not disabled else "partial",
        "enabled_files": enabled,
        "disabled_files": disabled,
    }
    write_json(YARA_ROOT / "manifests" / "third_party_yara_all.validation.json", combined)
    return combined


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", choices=["elastic", "neo23x0_signature_base"], action="append")
    parser.add_argument("--no-copy-disabled", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source_keys = args.source or list(PACK_SOURCES["third_party_yara_all"])
    manifests = []
    for source_key in source_keys:
        manifest = validate_source(source_key, copy_disabled=not args.no_copy_disabled)
        manifests.append(manifest)
        print(
            f"{source_key}: {manifest['enabled_file_count']} enabled, "
            f"{manifest['disabled_file_count']} disabled"
        )
    if set(source_keys) == set(PACK_SOURCES["third_party_yara_all"]):
        combined = build_all_manifest(manifests)
        print(
            f"third_party_yara_all: {combined['enabled_file_count']} enabled, "
            f"{combined['disabled_file_count']} disabled"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

