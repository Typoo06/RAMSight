# Process identity normalization helpers for job-local artifact correlation.

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from app.parsers.common import is_placeholder_value

PID_RE = re.compile(r"\b(?:pid\s*)?(\d+)\b", re.IGNORECASE)


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int | None
    process_name: str | None = None
    image_path: str | None = None
    command_line: str | None = None
    ppid: int | None = None
    parent_process_name: str | None = None


def normalize_text(value: Any) -> str | None:
    if is_placeholder_value(value):
        return None
    text = str(value).strip()
    return text or None


def normalize_process_name(value: Any) -> str | None:
    text = normalize_text(value)
    return text.lower() if text else None


def parse_pid(value: Any) -> int | None:
    if value is None or is_placeholder_value(value):
        return None
    if isinstance(value, int):
        return value
    text = str(value)
    match = PID_RE.search(text)
    return int(match.group(1)) if match else None


def _score_identity(candidate: ProcessIdentity) -> int:
    score = 0
    if candidate.process_name:
        score += 10
    if candidate.image_path:
        score += 5
    if candidate.command_line:
        score += 3
    if candidate.parent_process_name or candidate.ppid is not None:
        score += 1
    return score


def _identity_from_row(row: dict, pid: int | None = None) -> ProcessIdentity | None:
    resolved_pid = pid if pid is not None else parse_pid(row.get("pid") or row.get("process_id") or row.get("target_identifier"))
    if resolved_pid is None:
        return None
    return ProcessIdentity(
        pid=resolved_pid,
        process_name=normalize_text(row.get("name") or row.get("process_name")),
        image_path=normalize_text(row.get("image_path")),
        command_line=normalize_text(row.get("command_line") or row.get("command")),
        ppid=parse_pid(row.get("ppid") or row.get("parent_pid")),
        parent_process_name=normalize_text(row.get("parent_process_name") or row.get("parent_name")),
    )


def build_process_identity_resolver(artifacts: dict[str, list[dict]] | None) -> dict[int, ProcessIdentity]:
    artifacts = artifacts or {}
    by_pid: dict[int, ProcessIdentity] = {}

    def consider(row: dict, pid: int | None = None) -> None:
        identity = _identity_from_row(row, pid=pid)
        if identity is None or identity.pid is None:
            return
        current = by_pid.get(identity.pid)
        if current is None or _score_identity(identity) > _score_identity(current):
            by_pid[identity.pid] = identity

    for row in artifacts.get("process_artifacts", []):
        consider(row)
    for row in artifacts.get("command_artifacts", []):
        consider(row)
    for row in artifacts.get("network_artifacts", []):
        consider(row)
    for row in artifacts.get("module_artifacts", []):
        consider(row)
    for row in artifacts.get("memory_region_artifacts", []):
        consider(row)
    for row in artifacts.get("yara_matches", []):
        consider(row, pid=parse_pid(row.get("target_identifier")))
    return by_pid


def resolve_process_identity(row: dict, resolver: dict[int, ProcessIdentity] | None = None) -> ProcessIdentity:
    resolver = resolver or {}
    pid = parse_pid(row.get("pid") or row.get("target_identifier"))
    resolved = resolver.get(pid) if pid is not None else None
    row_identity = _identity_from_row(row, pid=pid)
    if resolved is None:
        return row_identity or ProcessIdentity(pid=pid)
    if row_identity is None:
        return resolved
    return ProcessIdentity(
        pid=pid,
        process_name=resolved.process_name or row_identity.process_name,
        image_path=resolved.image_path or row_identity.image_path,
        command_line=resolved.command_line or row_identity.command_line,
        ppid=resolved.ppid if resolved.ppid is not None else row_identity.ppid,
        parent_process_name=resolved.parent_process_name or row_identity.parent_process_name,
    )


def enrich_process_extra(extra_data: dict, resolver: dict[int, ProcessIdentity] | None = None) -> dict:
    identity = resolve_process_identity(extra_data, resolver)
    enriched = dict(extra_data)
    if identity.pid is not None:
        enriched["pid"] = identity.pid
    if identity.process_name:
        enriched["process_name"] = identity.process_name
    if identity.image_path:
        enriched.setdefault("image_path", identity.image_path)
    if identity.command_line:
        enriched.setdefault("command_line", identity.command_line)
    if identity.ppid is not None:
        enriched.setdefault("ppid", identity.ppid)
    if identity.parent_process_name:
        enriched.setdefault("parent_process_name", identity.parent_process_name)
    if identity.process_name:
        enriched["process_identity_resolved"] = True
    return enriched


def process_identity_key(analysis_job_id, pid: int | None, process_name: Any) -> tuple | None:
    normalized_name = normalize_process_name(process_name)
    if pid is not None and normalized_name:
        return analysis_job_id, pid, normalized_name
    if pid is not None:
        return analysis_job_id, pid, None
    if normalized_name:
        return analysis_job_id, None, normalized_name
    return None


def display_process_identity(pid: int | None, process_name: Any) -> str:
    text_name = normalize_text(process_name)
    if text_name and pid is not None:
        return f"{text_name} (PID {pid})"
    if text_name:
        return text_name
    if pid is not None:
        return f"PID {pid}"
    return "unknown process"
