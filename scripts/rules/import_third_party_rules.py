#!/usr/bin/env python3
"""Import third-party detection rule packs for RAMSight.

This script is an operator action. RAMSight runtime never depends on GitHub.
Imported upstream files are preserved unchanged; validation/build scripts decide
which YARA files become active runtime packs.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import shutil

from rule_pack_common import (
    REPO_ROOT,
    SOURCES,
    clone_source,
    copy_license_files,
    copy_tree_contents,
    iter_rule_files,
    relative_to_repo,
    utc_timestamp,
    write_json,
)


DEFAULT_CACHE_DIR = REPO_ROOT / ".cache" / "ramsight-rule-sources"


def source_ref(args: argparse.Namespace, source_key: str) -> str:
    return {
        "elastic": args.elastic_ref,
        "neo23x0_signature_base": args.neo23x0_ref,
        "sigmahq": args.sigma_ref,
    }[source_key]


def import_source(source_key: str, args: argparse.Namespace) -> dict:
    source = SOURCES[source_key]
    ref = source_ref(args, source_key)
    planned = {
        "source_repository": source.source_repository,
        "source_url": source.source_url,
        "ref": ref,
        "license": source.license_name,
        "imported_path": relative_to_repo(source.import_root),
        "rule_paths": list(source.rule_paths),
        "runtime_pack": source.runtime_pack,
    }
    if args.dry_run:
        return {
            **planned,
            "dry_run": True,
            "action": "would clone/copy source rule paths and license files",
        }

    cache_path = args.cache_dir / source.key
    commit_hash = clone_source(source, cache_path, ref, shallow=not args.full_clone)
    if source.import_root.exists():
        shutil.rmtree(source.import_root)
    source.import_root.mkdir(parents=True, exist_ok=True)

    copied_rule_roots = []
    for relative_rule_path in source.rule_paths:
        source_path = cache_path / relative_rule_path
        destination_path = source.import_root / relative_rule_path
        if copy_tree_contents(source_path, destination_path):
            copied_rule_roots.append(relative_rule_path)

    copied_license_files = copy_license_files(cache_path, source.import_root / "_upstream")
    rule_files = iter_rule_files(source.import_root, source.rule_extensions)
    manifest = {
        **planned,
        "dry_run": False,
        "commit_hash": commit_hash,
        "imported_at": utc_timestamp(),
        "copied_rule_roots": copied_rule_roots,
        "license_files": copied_license_files,
        "rule_file_count": len(rule_files),
        "rule_files": [relative_to_repo(path) for path in rule_files],
        "notes": (
            "Sigma rules are reference/future correlation content only and are never passed to YARA."
            if source_key == "sigmahq"
            else "YARA files are preserved unchanged; validate/build scripts select active files."
        ),
    }
    write_json(source.manifest_root / f"{source.key}.import.json", manifest)
    return manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="show planned imports without cloning or writing rule files")
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    parser.add_argument("--full-clone", action="store_true", help="allow checkout of arbitrary commit refs instead of shallow branch clone")
    parser.add_argument("--source", choices=sorted(SOURCES), action="append", help="source to import; default imports all")
    parser.add_argument("--elastic-ref", default=SOURCES["elastic"].default_ref)
    parser.add_argument("--neo23x0-ref", default=SOURCES["neo23x0_signature_base"].default_ref)
    parser.add_argument("--sigma-ref", default=SOURCES["sigmahq"].default_ref)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.cache_dir = args.cache_dir.resolve()
    sources = args.source or ["elastic", "neo23x0_signature_base", "sigmahq"]
    for source_key in sources:
        manifest = import_source(source_key, args)
        print(f"{source_key}: {manifest['action'] if args.dry_run else 'imported'}")
        print(f"  source: {manifest['source_url']} @ {manifest['ref']}")
        print(f"  destination: {manifest['imported_path']}")
        if not args.dry_run:
            print(f"  commit: {manifest['commit_hash']}")
            print(f"  rule files: {manifest['rule_file_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

