# Detection rule evaluation over normalized artifact rows.

from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Iterable

from app.detection.path_reputation import known_microsoft_appdata_path
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
MEMORY_COMMAND_KEYWORDS = {
    "downloadstring",
    "frombase64string",
    "invoke-expression",
    "mimikatz",
    "powershell -enc",
    "powershell.exe -enc",
    "rundll32",
    "shellcode",
}
YARA_SAMPLE_OFFSET_LIMIT = 5
YARA_SEVERITY_SCORES = {
    "low": 2,
    "medium": 5,
    "high": 8,
    "critical": 13,
}
DEMO_YARA_RULE_METADATA = {
    "ramsight_memory_powershell_encodedcommand_context": {
        "triage_severity": "medium",
        "confidence": "candidate",
        "noisy": False,
        "requires_correlation": True,
    },
    "ramsight_memory_powershell_downloadcradle_context": {
        "triage_severity": "medium",
        "confidence": "candidate",
        "noisy": False,
        "requires_correlation": True,
    },
    "ramsight_memory_processinjection_api_cluster": {
        "triage_severity": "high",
        "confidence": "candidate",
        "noisy": False,
        "requires_correlation": True,
    },
    "ramsight_memory_reflectiveloading_importcluster": {
        "triage_severity": "medium",
        "confidence": "candidate",
        "noisy": True,
        "requires_correlation": True,
    },
    "ramsight_memory_credentialdumping_context": {
        "triage_severity": "high",
        "confidence": "candidate",
        "noisy": False,
        "requires_correlation": True,
    },
    "ramsight_memory_livingoffland_command_context": {
        "triage_severity": "medium",
        "confidence": "candidate",
        "noisy": False,
        "requires_correlation": True,
    },
    "ramsight_memory_packedobfuscated_pe_context": {
        "triage_severity": "low",
        "confidence": "candidate",
        "noisy": True,
        "requires_correlation": True,
    },
    "ramsight_demo_pe_header_in_memory_candidate": {
        "triage_severity": "low",
        "confidence": "candidate",
        "noisy": True,
        "requires_correlation": True,
    },
    "ramsight_demo_injection_api_cluster": {
        "triage_severity": "medium",
        "confidence": "candidate",
        "noisy": False,
        "requires_correlation": True,
    },
    "ramsight_demo_encoded_powershell_memory_context": {
        "triage_severity": "medium",
        "confidence": "candidate",
        "noisy": False,
        "requires_correlation": True,
    },
}


def normalize_process_name(value: str | None) -> str:
    return (value or "").strip().lower()


def normalize_path(value: str | None, os_family: str | None = None) -> str:
    normalized = (value or "").strip().replace("\\", "/")
    if os_family == "windows":
        normalized = normalized.lower()
    return normalized


def normalize_key_text(value) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    return text or None


def truthy_metadata_value(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    return str(value).strip().lower() in {"true", "yes", "1"}


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
            elif match_type == "memory_injection_candidate":
                findings.extend(evaluate_memory_injection_candidates(rule, artifacts, context))
            elif match_type == "memory_region_with_network":
                findings.extend(evaluate_memory_network_correlation(rule, artifacts, context))
            elif match_type == "memory_region_with_suspicious_command":
                findings.extend(evaluate_memory_command_correlation(rule, artifacts, context))
            elif match_type == "memory_region_with_suspicious_module":
                findings.extend(evaluate_memory_module_correlation(rule, artifacts, context))
            elif match_type == "yara_match_in_process_memory":
                findings.extend(evaluate_yara_process_memory(rule, artifacts, context))
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


def memory_region_label(artifact: dict) -> str:
    start = artifact.get("start_address")
    end = artifact.get("end_address")
    if start and end:
        return f"{start}-{end}"
    return "address unavailable"


def memory_address_key(artifact: dict) -> tuple:
    return artifact.get("start_address"), artifact.get("end_address")


def process_memory_key(context: dict, rule: DetectionRule, artifact: dict, *extra_parts) -> tuple:
    return (
        context.get("analysis_job_id"),
        rule.id,
        artifact.get("pid"),
        normalize_key_text(artifact.get("process_name") or artifact.get("name")),
        *memory_address_key(artifact),
        *extra_parts,
    )


def memory_region_is_executable(artifact: dict) -> bool:
    protection = str(artifact.get("protection") or "")
    return bool(artifact.get("is_executable")) or "EXECUTE" in protection.upper()


def memory_region_is_suspicious(artifact: dict) -> bool:
    return memory_region_is_executable(artifact)


def memory_extra(artifact: dict, reason: str, linked_artifacts: dict | None = None) -> dict:
    extra = {
        **process_extra(artifact),
        "start_address": artifact.get("start_address"),
        "end_address": artifact.get("end_address"),
        "address_range": memory_region_label(artifact),
        "protection": artifact.get("protection"),
        "is_executable": artifact.get("is_executable"),
        "is_private": artifact.get("is_private"),
        "reasoning": reason,
        "requires_validation": True,
    }
    if linked_artifacts:
        extra["linked_artifacts"] = linked_artifacts
    return extra


def artifacts_by_pid(rows: list[dict]) -> dict[int, list[dict]]:
    indexed: dict[int, list[dict]] = {}
    for row in rows:
        pid = row.get("pid")
        if pid is None:
            continue
        indexed.setdefault(pid, []).append(row)
    return indexed


def suspicious_command_reason(command: str | None, keywords: list[str] | None = None) -> str | None:
    if not command:
        return None
    if command_has_encoded_powershell(command):
        return "encoded PowerShell command"
    lowered = command.lower()
    for keyword in sorted(keywords or MEMORY_COMMAND_KEYWORDS):
        if str(keyword).lower() in lowered:
            return f"suspicious command keyword: {keyword}"
    return None


def parse_pid_candidate(value) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value)
    match = re.search(r"\b\d+\b", text)
    return int(match.group(0)) if match else None


def yara_metadata(artifact: dict) -> dict:
    rule_name = normalize_key_text(artifact.get("rule_name")) or ""
    metadata = dict(DEMO_YARA_RULE_METADATA.get(rule_name, {}))
    extra_data = artifact.get("extra_data") or {}
    for nested_key in ["meta", "metadata"]:
        nested = extra_data.get(nested_key)
        if isinstance(nested, dict):
            metadata.update({str(key).lower(): value for key, value in nested.items()})
    for key in ["severity", "triage_severity", "confidence", "noisy", "requires_correlation"]:
        if key in extra_data:
            metadata[key] = extra_data[key]
    return metadata


def yara_risk_from_metadata(rule: DetectionRule, artifacts: list[dict], correlated: bool = False) -> tuple[str, int]:
    metadata = yara_metadata(artifacts[0]) if artifacts else {}
    severity = str(metadata.get("triage_severity") or metadata.get("severity") or rule.severity).lower()
    if severity not in YARA_SEVERITY_SCORES:
        severity = rule.severity

    confidence = str(metadata.get("confidence") or "").lower()
    noisy = truthy_metadata_value(metadata.get("noisy", False))
    requires_correlation = truthy_metadata_value(metadata.get("requires_correlation", False))

    if severity == "critical" and confidence not in {"high", "confirmed"}:
        severity = "high"
    if requires_correlation and not correlated and severity in {"high", "critical"}:
        severity = "medium"
    if noisy and not correlated:
        severity = "low"
    if noisy and correlated and severity in {"high", "critical"}:
        severity = "medium"
    if requires_correlation and correlated and severity == "low":
        severity = "medium"

    return severity, YARA_SEVERITY_SCORES.get(severity, rule.score)


def yara_is_high_confidence(metadata: dict) -> bool:
    confidence = str(metadata.get("confidence") or "").lower()
    noisy = truthy_metadata_value(metadata.get("noisy", False))
    return confidence in {"high", "confirmed"} and not noisy


def yara_should_use_job_summary(metadata: dict, correlated: bool = False) -> bool:
    if yara_is_high_confidence(metadata):
        return False
    noisy = truthy_metadata_value(metadata.get("noisy", False))
    requires_correlation = truthy_metadata_value(metadata.get("requires_correlation", False))
    return noisy or (requires_correlation and not correlated)


def display_yara_offset(artifact: dict) -> str | None:
    extra_data = artifact.get("extra_data") or {}
    raw_offset = extra_data.get("offset_raw")
    if raw_offset is not None:
        return str(raw_offset)
    offset = artifact.get("offset")
    if offset is None:
        return None
    return hex(offset) if isinstance(offset, int) else str(offset)


def sample_yara_offsets(artifacts: list[dict], limit: int = YARA_SAMPLE_OFFSET_LIMIT) -> list[str]:
    offsets = []
    seen = set()
    for artifact in artifacts:
        offset = display_yara_offset(artifact)
        if not offset or offset in seen:
            continue
        seen.add(offset)
        offsets.append(offset)
        if len(offsets) >= limit:
            break
    return offsets


def first_yara_process_name(artifacts: list[dict], fallback: str | None = None) -> str | None:
    for artifact in artifacts:
        value = artifact.get("process_name") or artifact.get("name")
        if value:
            return str(value)
    return fallback


def yara_group_key(context: dict, artifact: dict, pid: int | None, process_name: str | None) -> tuple:
    target_identifier = artifact.get("target_identifier")
    return (
        context.get("analysis_job_id"),
        pid if pid is not None else normalize_key_text(target_identifier),
        normalize_key_text(process_name),
        normalize_key_text(artifact.get("rule_name")),
        artifact.get("source_plugin"),
    )


def group_yara_matches(
    artifacts: list[dict],
    context: dict,
    memory_by_pid: dict[int, list[dict]] | None = None,
) -> list[tuple[dict, list[dict], int | None, str | None, list[dict]]]:
    grouped: dict[tuple, tuple[dict, list[dict], int | None, str | None, list[dict]]] = {}
    for artifact in artifacts:
        pid = parse_pid_candidate(artifact.get("target_identifier"))
        linked_regions = memory_by_pid.get(pid, []) if memory_by_pid and pid is not None else []
        region_process_name = first_yara_process_name(linked_regions)
        process_name = region_process_name or artifact.get("process_name")
        key = yara_group_key(context, artifact, pid, process_name)
        if key not in grouped:
            grouped[key] = (artifact, [], pid, process_name, linked_regions)
        grouped[key][1].append(artifact)
    return list(grouped.values())


def group_yara_matches_by_rule(artifacts: list[dict], context: dict) -> list[tuple[dict, list[dict]]]:
    grouped: dict[tuple, tuple[dict, list[dict]]] = {}
    for artifact in artifacts:
        key = (
            context.get("analysis_job_id"),
            normalize_key_text(artifact.get("rule_name")),
            artifact.get("source_plugin"),
        )
        if key not in grouped:
            grouped[key] = (artifact, [])
        grouped[key][1].append(artifact)
    return list(grouped.values())


def sample_yara_pids(artifacts: list[dict], limit: int = YARA_SAMPLE_OFFSET_LIMIT) -> list[int]:
    pids = []
    seen = set()
    for artifact in artifacts:
        pid = parse_pid_candidate(artifact.get("target_identifier"))
        if pid is None or pid in seen:
            continue
        seen.add(pid)
        pids.append(pid)
        if len(pids) >= limit:
            break
    return pids


def count_yara_affected_pids(artifacts: list[dict]) -> int:
    values = {parse_pid_candidate(artifact.get("target_identifier")) for artifact in artifacts}
    return len({pid for pid in values if pid is not None})


def yara_rule_summary_extra(artifacts: list[dict]) -> dict:
    first = artifacts[0]
    metadata = yara_metadata(first)
    return {
        "rule_name": first.get("rule_name"),
        "namespace": first.get("namespace"),
        "tags": first.get("tags"),
        "source_plugin": first.get("source_plugin"),
        "affected_pid_count": count_yara_affected_pids(artifacts),
        "total_match_count": len(artifacts),
        "sample_pids": sample_yara_pids(artifacts),
        "sample_offsets": sample_yara_offsets(artifacts),
        "yara_match_artifact_ids": [str(item.get("id")) for item in artifacts if item.get("id")],
        "noisy": truthy_metadata_value(metadata.get("noisy", False)),
        "requires_correlation": truthy_metadata_value(metadata.get("requires_correlation", False)),
        "confidence": metadata.get("confidence"),
        "triage_severity": metadata.get("triage_severity") or metadata.get("severity"),
        "summary_scope": "analysis_job",
        "reasoning": "Broad YARA matches are summarized by rule to avoid repeated process-level triage noise",
        "requires_validation": True,
    }


def yara_summary_extra(
    artifacts: list[dict],
    pid: int | None,
    process_name: str | None,
    linked_regions: list[dict] | None = None,
) -> dict:
    first = artifacts[0]
    metadata = yara_metadata(first)
    target_identifier = first.get("target_identifier")
    return {
        "pid": pid,
        "process_name": process_name,
        "rule_name": first.get("rule_name"),
        "namespace": first.get("namespace"),
        "tags": first.get("tags"),
        "target_identifier": target_identifier,
        "target_type": first.get("target_type"),
        "yara_match_count": len(artifacts),
        "sample_offsets": sample_yara_offsets(artifacts),
        "yara_match_artifact_ids": [str(item.get("id")) for item in artifacts if item.get("id")],
        "linked_memory_region_artifact_ids": [str(item.get("id")) for item in linked_regions or [] if item.get("id")],
        "confidence": metadata.get("confidence"),
        "noisy": truthy_metadata_value(metadata.get("noisy", False)),
        "requires_correlation": truthy_metadata_value(metadata.get("requires_correlation", False)),
        "triage_severity": metadata.get("triage_severity") or metadata.get("severity"),
        "reasoning": "YARA matches are summarized per process and rule to reduce repeated offset noise",
        "requires_validation": True,
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
        if known_microsoft_appdata_path(module_path, os_family):
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
        if not memory_region_is_suspicious(artifact):
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
                memory_extra(artifact, "executable memory region reported by a malfind-like plugin"),
            )
        )
    return findings


def evaluate_yara_matches(rule: DetectionRule, artifacts: dict[str, list[dict]], context: dict) -> list[FindingDraft]:
    findings = []
    summary_matches = []
    process_matches = []
    for artifact in artifacts.get(YARA_TABLE, []):
        metadata = yara_metadata(artifact)
        if yara_should_use_job_summary(metadata, correlated=False):
            summary_matches.append(artifact)
        else:
            process_matches.append(artifact)

    for artifact, matches in group_yara_matches_by_rule(summary_matches, context):
        severity, score = yara_risk_from_metadata(rule, matches, correlated=False)
        finding = make_finding(
            rule,
            context,
            artifact,
            f"YARA triage summary: {artifact.get('rule_name')}",
            f"YARA rule {artifact.get('rule_name')} matched {len(matches)} memory locations; this is a triage indicator requiring analyst validation and correlation.",
            YARA_TABLE,
            yara_rule_summary_extra(matches),
        )
        findings.append(FindingDraft(**{**finding.__dict__, "severity": severity, "score": score}))

    for artifact, matches, pid, process_name, linked_regions in group_yara_matches(process_matches, context):
        process_name = process_name or (None if pid is not None else artifact.get("target_identifier"))
        severity, score = yara_risk_from_metadata(rule, matches, correlated=bool(linked_regions))
        title_identity = process_identity({"pid": pid, "process_name": process_name})
        finding = make_finding(
            rule,
            context,
            artifact,
            f"YARA match candidate: {artifact.get('rule_name')}",
            f"YARA rule {artifact.get('rule_name')} matched {title_identity}; this is a candidate signal requiring analyst validation.",
            YARA_TABLE,
            yara_summary_extra(matches, pid, process_name, linked_regions),
        )
        findings.append(FindingDraft(**{**finding.__dict__, "severity": severity, "score": score}))
    return findings


def evaluate_memory_injection_candidates(rule: DetectionRule, artifacts: dict[str, list[dict]], context: dict) -> list[FindingDraft]:
    source_plugins = set(rule.match.get("source_plugins") or [])
    findings = []
    seen = set()
    for artifact in artifacts.get(MEMORY_REGION_TABLE, []):
        if source_plugins and artifact.get("source_plugin") not in source_plugins:
            continue
        if not memory_region_is_suspicious(artifact):
            continue
        dedupe_key = process_memory_key(context, rule, artifact)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        findings.append(
            make_finding(
                rule,
                context,
                artifact,
                f"Process injection candidate: {process_identity(artifact)}",
                f"{process_identity(artifact)} has executable memory at {memory_region_label(artifact)}; this is a memory-only payload candidate and requires analyst validation.",
                MEMORY_REGION_TABLE,
                memory_extra(artifact, "executable/private memory region compatible with process injection candidate"),
            )
        )
    return findings


def evaluate_memory_network_correlation(rule: DetectionRule, artifacts: dict[str, list[dict]], context: dict) -> list[FindingDraft]:
    network_by_pid = artifacts_by_pid(artifacts.get(NETWORK_TABLE, []))
    findings = []
    seen = set()
    for region in artifacts.get(MEMORY_REGION_TABLE, []):
        if not memory_region_is_suspicious(region) or region.get("pid") is None:
            continue
        for network in network_by_pid.get(region.get("pid"), []):
            remote_address = network.get("remote_address")
            if not is_public_remote_address(remote_address):
                continue
            dedupe_key = (
                *process_memory_key(context, rule, region),
                normalize_key_text(remote_address),
                network.get("remote_port"),
            )
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            findings.append(
                make_finding(
                    rule,
                    context,
                    region,
                    f"Executable memory region with network activity: {process_identity(region)}",
                    f"{process_identity(region)} has suspicious executable memory and a public remote network connection; this is a candidate requiring validation.",
                    MEMORY_REGION_TABLE,
                    memory_extra(
                        region,
                        "executable memory region correlated with public remote network activity by PID",
                        {
                            "memory_region_artifact_id": str(region.get("id")),
                            "network_artifact_id": str(network.get("id")),
                            "remote_address": remote_address,
                            "remote_port": network.get("remote_port"),
                            "network_source_plugin": network.get("source_plugin"),
                        },
                    ),
                )
            )
    return findings


def evaluate_memory_command_correlation(rule: DetectionRule, artifacts: dict[str, list[dict]], context: dict) -> list[FindingDraft]:
    command_by_pid = artifacts_by_pid(artifacts.get(COMMAND_TABLE, []))
    keywords = rule.match.get("keywords") or sorted(MEMORY_COMMAND_KEYWORDS)
    findings = []
    seen = set()
    for region in artifacts.get(MEMORY_REGION_TABLE, []):
        if not memory_region_is_suspicious(region) or region.get("pid") is None:
            continue
        for command in command_by_pid.get(region.get("pid"), []):
            reason = suspicious_command_reason(command.get("command"), keywords)
            if not reason:
                continue
            dedupe_key = process_memory_key(
                context,
                rule,
                region,
                normalize_key_text(reason),
                normalize_key_text(command.get("command")),
            )
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            findings.append(
                make_finding(
                    rule,
                    context,
                    region,
                    f"Executable memory region with suspicious command line: {process_identity(region)}",
                    f"{process_identity(region)} has suspicious executable memory and command-line evidence ({reason}); this is a candidate requiring validation.",
                    MEMORY_REGION_TABLE,
                    memory_extra(
                        region,
                        f"executable memory region correlated with {reason}",
                        {
                            "memory_region_artifact_id": str(region.get("id")),
                            "command_artifact_id": str(command.get("id")),
                            "command_excerpt": str(command.get("command") or "")[:500],
                            "command_source_plugin": command.get("source_plugin"),
                        },
                    ),
                )
            )
    return findings


def evaluate_memory_module_correlation(rule: DetectionRule, artifacts: dict[str, list[dict]], context: dict) -> list[FindingDraft]:
    os_family = (context.get("os_family") or "unknown").lower()
    module_by_pid = artifacts_by_pid(artifacts.get(MODULE_TABLE, []))
    fragments = [normalize_path(fragment, os_family) for fragment in rule.match.get("suspicious_path_fragments") or []]
    findings = []
    seen = set()
    for region in artifacts.get(MEMORY_REGION_TABLE, []):
        if not memory_region_is_suspicious(region) or region.get("pid") is None:
            continue
        for module in module_by_pid.get(region.get("pid"), []):
            module_path = module.get("module_path")
            if not is_path_like(module_path, os_family):
                continue
            normalized_path = normalize_path(module_path, os_family)
            matched = [fragment for fragment in fragments if fragment in normalized_path]
            if not matched:
                continue
            reputation = known_microsoft_appdata_path(module_path, os_family)
            module_key = reputation.normalized_root if reputation else normalized_path
            dedupe_key = process_memory_key(context, rule, region, module_key)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            linked_artifacts = {
                "memory_region_artifact_id": str(region.get("id")),
                "module_artifact_id": str(module.get("id")),
                "module_name": module.get("module_name"),
                "module_path": module_path,
                "matched_path_fragments": matched,
                "module_source_plugin": module.get("source_plugin"),
            }
            title = f"Executable memory region with suspicious module path: {process_identity(region)}"
            description = (
                f"{process_identity(region)} has suspicious executable memory and a module mapped from a user-writable path; "
                "this requires analyst validation."
            )
            reason = "executable memory region correlated with suspicious/user-writable module path by PID"
            severity = rule.severity
            score = rule.score
            if reputation:
                linked_artifacts.update(
                    {
                        "known_microsoft_appdata_module": True,
                        "module_app_name": reputation.app_name,
                        "module_app_root": reputation.normalized_root,
                        "module_context_only": True,
                    }
                )
                title = f"Executable memory region with Microsoft AppData module context: {process_identity(region)}"
                description = (
                    f"{process_identity(region)} has suspicious executable memory and a module loaded from a known Microsoft "
                    "AppData application path; treat the module path as supporting context that requires validation."
                )
                reason = "executable memory region correlated with known Microsoft AppData module context by PID"
                severity = "medium"
                score = min(rule.score, 5)
            finding = make_finding(
                rule,
                context,
                region,
                title,
                description,
                MEMORY_REGION_TABLE,
                memory_extra(region, reason, linked_artifacts),
            )
            findings.append(FindingDraft(**{**finding.__dict__, "severity": severity, "score": score}))
    return findings


def evaluate_yara_process_memory(rule: DetectionRule, artifacts: dict[str, list[dict]], context: dict) -> list[FindingDraft]:
    memory_by_pid = artifacts_by_pid(artifacts.get(MEMORY_REGION_TABLE, []))
    findings = []
    process_memory_matches = []
    for yara_match in artifacts.get(YARA_TABLE, []):
        source_plugin = yara_match.get("source_plugin")
        target_type = str(yara_match.get("target_type") or "").lower()
        if source_plugin not in {"windows.vadyarascan", "linux.vmayarascan"} and target_type != "process_memory":
            continue
        process_memory_matches.append(yara_match)

    for yara_match, matches, pid, process_name, linked_regions in group_yara_matches(process_memory_matches, context, memory_by_pid):
        metadata = yara_metadata(yara_match)
        if yara_should_use_job_summary(metadata, correlated=bool(linked_regions)):
            continue
        process_name = process_name or (None if pid is not None else yara_match.get("target_identifier"))
        title_identity = process_identity({"pid": pid, "process_name": process_name})
        severity, score = yara_risk_from_metadata(rule, matches, correlated=bool(linked_regions))
        findings.append(
            FindingDraft(**{**make_finding(
                rule,
                context,
                yara_match,
                f"YARA match in process memory: {title_identity}",
                f"YARA rule {yara_match.get('rule_name')} matched process memory for {title_identity}; this is suspicious and requires analyst validation.",
                YARA_TABLE,
                yara_summary_extra(matches, pid, process_name, linked_regions),
            ).__dict__, "severity": severity, "score": score})
        )
    return findings
