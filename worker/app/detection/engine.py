# Detection rule evaluation over normalized artifact rows.

from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Iterable

from app.detection.rules import DetectionRule, FindingDraft, applies_to_os
from app.parsers.common import is_path_like

PROCESS_TABLE = "process_artifacts"
NETWORK_TABLE = "network_artifacts"
MODULE_TABLE = "module_artifacts"
MEMORY_REGION_TABLE = "memory_region_artifacts"
COMMAND_TABLE = "command_artifacts"
YARA_TABLE = "yara_matches"

BASE64_TOKEN_RE = re.compile(r"^[A-Za-z0-9+/]{40,}={0,2}$")
ENCODED_FLAG_RE = re.compile(r"(^|\s)([-/](?:enc|encodedcommand))(?=$|\s|:)", re.IGNORECASE)
LOGGER = logging.getLogger(__name__)
KNOWN_WINDOWS_SYSTEM_PROCESSES = {
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "lsm.exe",
    "svchost.exe",
    "explorer.exe",
}
DEFAULT_WINDOWS_SYSTEM_PATHS = {
    "explorer.exe": ["C:/Windows/"],
}


def normalize_process_name(value: str | None) -> str:
    return (value or "").strip().lower()


def normalize_path(value: str | None, os_family: str | None = None) -> str:
    normalized = (value or "").strip().replace("\\", "/")
    if os_family == "windows":
        normalized = normalized.lower()
    return normalized


def process_identity(artifact: dict) -> str:
    name = artifact.get("name") or artifact.get("process_name") or "unknown process"
    pid = artifact.get("pid")
    if pid is not None:
        return f"{name} (PID {pid})"
    return str(name)


def is_public_remote_address(value: str | None) -> bool:
    if not value:
        return False
    text = value.strip().strip("[]")
    if not text or text == "0.0.0.0":
        return False
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    return not (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    )


def command_has_encoded_powershell(command: str | None) -> bool:
    if not command:
        return False
    lowered = command.lower()
    if "powershell" not in lowered and "pwsh" not in lowered:
        return False
    if ENCODED_FLAG_RE.search(command):
        return True
    return any(BASE64_TOKEN_RE.match(token.strip('"\'')) for token in command.split())


def evaluate_rules(rules: Iterable[DetectionRule], artifacts: dict[str, list[dict]], context: dict) -> list[FindingDraft]:
    os_family = (context.get("os_family") or "unknown").lower()
    findings: list[FindingDraft] = []
    for rule in rules:
        if not rule.enabled or not applies_to_os(rule, os_family):
            continue
        match_type = rule.match.get("type")
        try:
            if match_type == "system_process_wrong_path":
                findings.extend(evaluate_system_process_wrong_path(rule, artifacts, context))
            elif match_type == "suspicious_parent_child":
                findings.extend(evaluate_suspicious_parent_child(rule, artifacts, context))
            elif match_type == "psscan_only_process":
                findings.extend(evaluate_psscan_only_process(rule, artifacts, context))
            elif match_type == "encoded_powershell":
                findings.extend(evaluate_encoded_powershell(rule, artifacts, context))
            elif match_type == "suspicious_command_keywords":
                findings.extend(evaluate_suspicious_command_keywords(rule, artifacts, context))
            elif match_type == "external_network_connection":
                findings.extend(evaluate_external_network_connections(rule, artifacts, context))
            elif match_type == "suspicious_module_path":
                findings.extend(evaluate_suspicious_module_path(rule, artifacts, context))
            elif match_type == "malfind_memory_region":
                findings.extend(evaluate_memory_regions(rule, artifacts, context))
            elif match_type == "yara_match":
                findings.extend(evaluate_yara_matches(rule, artifacts, context))
        except Exception as exc:  # noqa: BLE001 - one bad rule should not stop detection.
            LOGGER.warning("skipping detection rule %s after safe error: %s", rule.id, str(exc)[:200])
    return findings


def make_finding(
    rule: DetectionRule,
    context: dict,
    artifact: dict | None,
    title: str,
    description: str,
    artifact_type: str | None,
    extra_data: dict | None = None,
) -> FindingDraft:
    artifact = artifact or {}
    return FindingDraft(
        analysis_job_id=context["analysis_job_id"],
        evidence_id=context["evidence_id"],
        plugin_result_id=artifact.get("plugin_result_id"),
        os_family=(context.get("os_family") or "unknown").lower(),
        os_scope=rule.os_scope,
        source_plugin=artifact.get("source_plugin"),
        rule_id=rule.id,
        rule_name=rule.name,
        category=rule.category,
        severity=rule.severity,
        score=rule.score,
        title=title,
        description=description,
        artifact_type=artifact_type,
        artifact_id=str(artifact.get("id")) if artifact.get("id") else None,
        recommendation=rule.recommendation,
        extra_data=extra_data or {},
    )


def process_extra(artifact: dict) -> dict:
    return {
        "pid": artifact.get("pid"),
        "ppid": artifact.get("ppid"),
        "process_name": artifact.get("name") or artifact.get("process_name"),
        "image_path": artifact.get("image_path"),
        "command_line": artifact.get("command_line"),
        "source_plugin": artifact.get("source_plugin"),
    }


def evaluate_system_process_wrong_path(rule: DetectionRule, artifacts: dict[str, list[dict]], context: dict) -> list[FindingDraft]:
    os_family = (context.get("os_family") or "unknown").lower()
    configured_names = {normalize_process_name(name) for name in rule.match.get("process_names") or []}
    process_names = (configured_names or KNOWN_WINDOWS_SYSTEM_PROCESSES) & KNOWN_WINDOWS_SYSTEM_PROCESSES
    expected_paths = [normalize_path(path, os_family) for path in rule.match.get("expected_paths") or []]
    findings = []
    seen = set()
    for artifact in artifacts.get(PROCESS_TABLE, []):
        name = normalize_process_name(artifact.get("name"))
        image_path = artifact.get("image_path")
        if name not in process_names or not is_path_like(image_path, os_family):
            continue
        paths_for_process = [normalize_path(path, os_family) for path in DEFAULT_WINDOWS_SYSTEM_PATHS.get(name, [])] or expected_paths
        normalized_path = normalize_path(image_path, os_family)
        if any(normalized_path.startswith(expected_path) for expected_path in paths_for_process):
            continue
        dedupe_key = (name, artifact.get("pid"), normalized_path)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        findings.append(
            make_finding(
                rule,
                context,
                artifact,
                f"System process path anomaly: {process_identity(artifact)}",
                f"{process_identity(artifact)} is running from {image_path}, outside the expected system directory.",
                PROCESS_TABLE,
                {**process_extra(artifact), "image_path": image_path, "expected_paths": paths_for_process},
            )
        )
    return findings


def evaluate_suspicious_parent_child(rule: DetectionRule, artifacts: dict[str, list[dict]], context: dict) -> list[FindingDraft]:
    processes = artifacts.get(PROCESS_TABLE, [])
    by_pid = {artifact.get("pid"): artifact for artifact in processes if artifact.get("pid") is not None}
    pairs = {(normalize_process_name(pair.get("parent")), normalize_process_name(pair.get("child"))) for pair in rule.match.get("pairs") or []}
    findings = []
    for artifact in processes:
        parent = by_pid.get(artifact.get("ppid"))
        if not parent:
            continue
        pair = (normalize_process_name(parent.get("name")), normalize_process_name(artifact.get("name")))
        if pair not in pairs:
            continue
        findings.append(
            make_finding(
                rule,
                context,
                artifact,
                f"Suspicious parent-child relationship: {parent.get('name')} -> {artifact.get('name')}",
                f"{parent.get('name')} spawned {process_identity(artifact)}, matching a suspicious relationship rule.",
                PROCESS_TABLE,
                {**process_extra(artifact), "parent_pid": parent.get("pid"), "parent_name": parent.get("name")},
            )
        )
    return findings


def evaluate_psscan_only_process(rule: DetectionRule, artifacts: dict[str, list[dict]], context: dict) -> list[FindingDraft]:
    processes = artifacts.get(PROCESS_TABLE, [])
    pslist_pids = {artifact.get("pid") for artifact in processes if artifact.get("source_plugin") == "windows.pslist" and artifact.get("pid") is not None}
    findings = []
    for artifact in processes:
        if artifact.get("source_plugin") != "windows.psscan" or artifact.get("pid") is None:
            continue
        if artifact.get("pid") in pslist_pids:
            continue
        findings.append(
            make_finding(
                rule,
                context,
                artifact,
                f"Hidden process candidate: {process_identity(artifact)}",
                f"{process_identity(artifact)} appears in psscan but not pslist by PID; treat this as a hidden process candidate.",
                PROCESS_TABLE,
                process_extra(artifact),
            )
        )
    return findings


def evaluate_encoded_powershell(rule: DetectionRule, artifacts: dict[str, list[dict]], context: dict) -> list[FindingDraft]:
    findings = []
    for artifact in artifacts.get(COMMAND_TABLE, []):
        command = artifact.get("command")
        if not command_has_encoded_powershell(command):
            continue
        findings.append(
            make_finding(
                rule,
                context,
                artifact,
                "Encoded PowerShell command",
                "A PowerShell command uses encoded-command syntax or a long Base64-like argument.",
                COMMAND_TABLE,
                {"pid": artifact.get("pid"), "process_name": artifact.get("process_name"), "command_excerpt": command[:500]},
            )
        )
    return findings


def evaluate_suspicious_command_keywords(rule: DetectionRule, artifacts: dict[str, list[dict]], context: dict) -> list[FindingDraft]:
    keywords = [str(keyword).lower() for keyword in rule.match.get("keywords") or []]
    findings = []
    for artifact in artifacts.get(COMMAND_TABLE, []):
        command = artifact.get("command") or ""
        lowered = command.lower()
        matched = [keyword for keyword in keywords if keyword in lowered]
        if not matched:
            continue
        findings.append(
            make_finding(
                rule,
                context,
                artifact,
                "Suspicious command line keyword",
                "A command line contains keywords commonly associated with suspicious activity.",
                COMMAND_TABLE,
                {"pid": artifact.get("pid"), "process_name": artifact.get("process_name"), "matched_keywords": matched},
            )
        )
    return findings


def evaluate_external_network_connections(rule: DetectionRule, artifacts: dict[str, list[dict]], context: dict) -> list[FindingDraft]:
    findings = []
    for artifact in artifacts.get(NETWORK_TABLE, []):
        remote_address = artifact.get("remote_address")
        if not is_public_remote_address(remote_address):
            continue
        findings.append(
            make_finding(
                rule,
                context,
                artifact,
                "External network connection",
                "A network artifact has a public remote IP address.",
                NETWORK_TABLE,
                {
                    "pid": artifact.get("pid"),
                    "process_name": artifact.get("process_name"),
                    "remote_address": remote_address,
                    "remote_port": artifact.get("remote_port"),
                    "state": artifact.get("state"),
                },
            )
        )
    return findings


def evaluate_suspicious_module_path(rule: DetectionRule, artifacts: dict[str, list[dict]], context: dict) -> list[FindingDraft]:
    os_family = (context.get("os_family") or "unknown").lower()
    fragments = [normalize_path(fragment, os_family) for fragment in rule.match.get("suspicious_path_fragments") or []]
    findings = []
    seen = set()
    for artifact in artifacts.get(MODULE_TABLE, []):
        module_path = artifact.get("module_path")
        if not is_path_like(module_path, os_family):
            continue
        normalized_path = normalize_path(module_path, os_family)
        matched = [fragment for fragment in fragments if fragment in normalized_path]
        if not matched:
            continue
        dedupe_key = (artifact.get("pid"), normalize_process_name(artifact.get("process_name")), normalized_path)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        findings.append(
            make_finding(
                rule,
                context,
                artifact,
                f"Suspicious module path in {process_identity(artifact)}",
                f"A loaded module is mapped from a temporary or user-writable path: {module_path}.",
                MODULE_TABLE,
                {
                    "pid": artifact.get("pid"),
                    "process_name": artifact.get("process_name"),
                    "module_name": artifact.get("module_name"),
                    "module_path": module_path,
                    "matched_path_fragments": matched,
                },
            )
        )
    return findings


def evaluate_memory_regions(rule: DetectionRule, artifacts: dict[str, list[dict]], context: dict) -> list[FindingDraft]:
    source_plugins = set(rule.match.get("source_plugins") or [])
    findings = []
    seen = set()
    for artifact in artifacts.get(MEMORY_REGION_TABLE, []):
        if source_plugins and artifact.get("source_plugin") not in source_plugins:
            continue
        if not artifact.get("is_executable") and artifact.get("source_plugin") != "windows.malfind":
            continue
        start = artifact.get("start_address")
        end = artifact.get("end_address")
        region_label = f"{start}-{end}" if start and end else "address unavailable"
        dedupe_key = (artifact.get("pid"), artifact.get("source_plugin"), start, end, artifact.get("protection"))
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        findings.append(
            make_finding(
                rule,
                context,
                artifact,
                f"Suspicious executable memory region in {process_identity(artifact)}",
                f"A malfind-like plugin reported a suspicious executable memory region ({region_label}); this is an injection candidate and requires analyst validation.",
                MEMORY_REGION_TABLE,
                {
                    "pid": artifact.get("pid"),
                    "process_name": artifact.get("process_name"),
                    "start_address": artifact.get("start_address"),
                    "end_address": artifact.get("end_address"),
                    "protection": artifact.get("protection"),
                    "is_executable": artifact.get("is_executable"),
                    "is_private": artifact.get("is_private"),
                },
            )
        )
    return findings


def evaluate_yara_matches(rule: DetectionRule, artifacts: dict[str, list[dict]], context: dict) -> list[FindingDraft]:
    findings = []
    for artifact in artifacts.get(YARA_TABLE, []):
        severity = rule.severity
        score = rule.score
        extra_data = artifact.get("extra_data") or {}
        if str(extra_data.get("severity", "")).lower() == "critical":
            severity = "critical"
            score = max(score, 13)
        finding = make_finding(
            rule,
            context,
            artifact,
            "YARA match",
            "A YARA rule matched memory content or a scanned memory target.",
            YARA_TABLE,
            {
                "rule_name": artifact.get("rule_name"),
                "namespace": artifact.get("namespace"),
                "tags": artifact.get("tags"),
                "target_type": artifact.get("target_type"),
                "target_identifier": artifact.get("target_identifier"),
                "offset": artifact.get("offset"),
            },
        )
        findings.append(FindingDraft(**{**finding.__dict__, "severity": severity, "score": score}))
    return findings
