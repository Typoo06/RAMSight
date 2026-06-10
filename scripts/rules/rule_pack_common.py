#!/usr/bin/env python3
"""Shared helpers for RAMSight third-party rule pack scripts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re
import shutil
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_ROOT = REPO_ROOT / "rules"
YARA_ROOT = RULES_ROOT / "yara"
SIGMA_ROOT = RULES_ROOT / "sigma"
YARA_EXTENSIONS = {".yar", ".yara"}
SIGMA_EXTENSIONS = {".yml", ".yaml"}
RULE_RE = re.compile(r"(?m)^\s*(?:private\s+|global\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)\b")
META_BLOCK_RE = re.compile(r"(?ms)\bmeta\s*:\s*(.*?)(?:\n\s*strings\s*:|\n\s*condition\s*:)")
META_LINE_RE = re.compile(r"(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$")


@dataclass(frozen=True)
class SourceDefinition:
    key: str
    source_repository: str
    source_url: str
    default_ref: str
    license_name: str
    rule_paths: tuple[str, ...]
    import_root: Path
    manifest_root: Path
    rule_extensions: set[str]
    runtime_pack: str | None = None


SOURCES = {
    "elastic": SourceDefinition(
        key="elastic",
        source_repository="elastic/protections-artifacts",
        source_url="https://github.com/elastic/protections-artifacts",
        default_ref="main",
        license_name="Elastic License 2.0",
        rule_paths=("yara",),
        import_root=YARA_ROOT / "third_party" / "elastic",
        manifest_root=YARA_ROOT / "manifests",
        rule_extensions=YARA_EXTENSIONS,
        runtime_pack="elastic_yara",
    ),
    "neo23x0_signature_base": SourceDefinition(
        key="neo23x0_signature_base",
        source_repository="Neo23x0/signature-base",
        source_url="https://github.com/Neo23x0/signature-base",
        default_ref="master",
        license_name="Detection Rule License 1.1",
        rule_paths=("yara", "vendor/yara"),
        import_root=YARA_ROOT / "third_party" / "neo23x0_signature_base",
        manifest_root=YARA_ROOT / "manifests",
        rule_extensions=YARA_EXTENSIONS,
        runtime_pack="neo23x0_yara",
    ),
    "sigmahq": SourceDefinition(
        key="sigmahq",
        source_repository="SigmaHQ/sigma",
        source_url="https://github.com/SigmaHQ/sigma",
        default_ref="master",
        license_name="Detection Rule License 1.1",
        rule_paths=(
            "rules",
            "rules-dfir",
            "rules-emerging-threats",
            "rules-threat-hunting",
            "rules-compliance",
            "rules-placeholder",
        ),
        import_root=SIGMA_ROOT / "third_party" / "sigmahq",
        manifest_root=SIGMA_ROOT / "manifests",
        rule_extensions=SIGMA_EXTENSIONS,
        runtime_pack=None,
    ),
}

PACK_SOURCES = {
    "elastic_yara": ("elastic",),
    "neo23x0_yara": ("neo23x0_signature_base",),
    "third_party_yara_all": ("elastic", "neo23x0_signature_base"),
}

LICENSE_FILENAMES = {
    "LICENSE",
    "LICENSE.txt",
    "LICENSE.md",
    "NOTICE",
    "NOTICE.txt",
    "README.md",
    "Code_of_Conduct.md",
}


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def run_command(command: list[str], cwd: Path | None = None) -> str:
    completed = subprocess.run(command, cwd=cwd, check=True, capture_output=True, text=True)
    return completed.stdout.strip()


def git_commit(path: Path) -> str:
    return run_command(["git", "rev-parse", "HEAD"], cwd=path)


def clone_source(source: SourceDefinition, destination: Path, ref: str, shallow: bool = True) -> str:
    if destination.exists():
        shutil.rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    command = ["git", "clone"]
    if shallow:
        command.extend(["--depth", "1", "--branch", ref])
    command.extend([source.source_url, str(destination)])
    run_command(command)
    if not shallow:
        run_command(["git", "checkout", ref], cwd=destination)
    return git_commit(destination)


def copy_tree_contents(source: Path, destination: Path) -> int:
    if not source.exists():
        return 0
    if destination.exists():
        shutil.rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, destination)
    return 1


def copy_license_files(source_repo: Path, destination: Path) -> list[str]:
    copied = []
    destination.mkdir(parents=True, exist_ok=True)
    for name in sorted(LICENSE_FILENAMES):
        src = source_repo / name
        if not src.is_file():
            continue
        shutil.copy2(src, destination / name)
        copied.append(name)
    return copied


def iter_rule_files(root: Path, extensions: set[str]) -> list[Path]:
    if not root.exists():
        return []
    return sorted(path for path in root.rglob("*") if path.is_file() and path.suffix.lower() in extensions)


def relative_to_repo(path: Path) -> str:
    return path.resolve().relative_to(REPO_ROOT.resolve()).as_posix()


def count_yara_rules(path: Path) -> int:
    return len(RULE_RE.findall(path.read_text(encoding="utf-8", errors="replace")))


def extract_yara_rule_metadata(path: Path) -> dict[str, dict]:
    text = path.read_text(encoding="utf-8", errors="replace")
    rule_names = RULE_RE.findall(text)
    meta_match = META_BLOCK_RE.search(text)
    metadata = {}
    meta = {}
    if meta_match:
        for key, raw_value in META_LINE_RE.findall(meta_match.group(1)):
            value = raw_value.strip().strip('"')
            meta[key.lower()] = value
    for rule_name in rule_names:
        metadata[rule_name] = dict(meta)
    return metadata

