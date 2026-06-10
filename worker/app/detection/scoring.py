# Process-level risk aggregation helpers.

from collections import defaultdict

from app.detection.path_reputation import known_microsoft_appdata_path
from app.detection.process_identity import build_process_identity_resolver, enrich_process_extra, process_identity_key
from app.detection.rules import FindingDraft
from app.parsers.common import is_placeholder_value

MEMORY_REGION_RULE_IDS = {
    "SUSPICIOUS_EXECUTABLE_MEMORY_REGION",
    "MEMORY_PROCESS_INJECTION_CANDIDATE",
}
NETWORK_CORRELATION_RULE_IDS = {"MEMORY_REGION_WITH_NETWORK_ACTIVITY", "EXTERNAL_NETWORK_CONNECTION"}
COMMAND_CORRELATION_RULE_IDS = {
    "MEMORY_REGION_WITH_SUSPICIOUS_COMMAND",
    "WIN_ENCODED_POWERSHELL",
    "WIN_SUSPICIOUS_COMMAND_KEYWORDS",
}
MODULE_CORRELATION_RULE_IDS = {"MEMORY_REGION_WITH_SUSPICIOUS_MODULE", "WIN_SUSPICIOUS_MODULE_PATH"}
YARA_RULE_IDS = {"YARA_MATCH", "YARA_MATCH_IN_PROCESS_MEMORY"}


def severity_for_score(score: int, scoring_config: dict) -> str:
    for severity, bounds in (scoring_config.get("risk_levels") or {}).items():
        minimum = bounds.get("min", 0)
        maximum = bounds.get("max")
        if score >= minimum and (maximum is None or score <= maximum):
            return str(severity)
    return "critical" if score >= 13 else "low"


def normalize_text(value) -> str | None:
    if is_placeholder_value(value):
        return None
    return str(value).strip().lower()


def normalize_path(value) -> str | None:
    text = normalize_text(value)
    if text is None:
        return None
    return text.replace("\\", "/")


def process_key_from_finding(finding: FindingDraft) -> tuple | None:
    extra_data = finding.extra_data or {}
    pid = extra_data.get("pid")
    process_name = normalize_text(extra_data.get("process_name"))
    canonical = process_identity_key(finding.analysis_job_id, pid, process_name)
    if canonical is not None:
        return canonical
    if pid is not None:
        return finding.analysis_job_id, pid, None
    if process_name:
        return finding.analysis_job_id, None, process_name
    return None


def finding_with_resolved_identity(finding: FindingDraft, resolver: dict | None = None) -> FindingDraft:
    extra_data = finding.extra_data or {}
    enriched = enrich_process_extra(extra_data, resolver)
    if enriched == extra_data:
        return finding
    return FindingDraft(**{**finding.__dict__, "extra_data": enriched})


def linked_artifacts_for_finding(finding: FindingDraft) -> dict:
    extra_data = finding.extra_data or {}
    linked_artifacts = extra_data.get("linked_artifacts") or {}
    return linked_artifacts if isinstance(linked_artifacts, dict) else {}


def microsoft_module_reputation(finding: FindingDraft):
    extra_data = finding.extra_data or {}
    linked_artifacts = linked_artifacts_for_finding(finding)
    if extra_data.get("known_microsoft_appdata_module") or linked_artifacts.get("known_microsoft_appdata_module"):
        path = linked_artifacts.get("module_path") or extra_data.get("module_path")
        return known_microsoft_appdata_path(path, finding.os_family)
    path = linked_artifacts.get("module_path") or extra_data.get("module_path")
    return known_microsoft_appdata_path(path, finding.os_family)


def module_component_path_key(finding: FindingDraft) -> str | None:
    extra_data = finding.extra_data or {}
    linked_artifacts = linked_artifacts_for_finding(finding)
    reputation = microsoft_module_reputation(finding)
    if reputation:
        return f"known-microsoft-appdata:{reputation.app_name}:{reputation.normalized_root}"
    return normalize_path(linked_artifacts.get("module_path") or extra_data.get("module_path"))


def component_key(finding: FindingDraft) -> tuple:
    extra_data = finding.extra_data or {}
    linked_artifacts = linked_artifacts_for_finding(finding)
    if finding.rule_id in YARA_RULE_IDS or finding.artifact_type == "yara_matches":
        return (
            "yara_match",
            extra_data.get("pid"),
            normalize_text(extra_data.get("process_name")),
            extra_data.get("target_identifier"),
            normalize_text(extra_data.get("rule_name")),
            finding.source_plugin,
        )
    module_path_key = module_component_path_key(finding)
    return (
        finding.rule_id,
        finding.category,
        extra_data.get("pid"),
        normalize_text(extra_data.get("process_name")),
        normalize_path(extra_data.get("image_path")),
        module_path_key,
        extra_data.get("start_address"),
        extra_data.get("end_address"),
        linked_artifacts.get("remote_address") or extra_data.get("remote_address"),
        linked_artifacts.get("remote_port") or extra_data.get("remote_port"),
        normalize_text(linked_artifacts.get("command_excerpt") or extra_data.get("command_excerpt")),
        module_path_key,
        extra_data.get("rule_name"),
        extra_data.get("offset"),
    )


def evidence_groups_for_finding(finding: FindingDraft) -> set[str]:
    if finding.rule_id == "MEMORY_REGION_WITH_NETWORK_ACTIVITY":
        return {"memory_region", "network_endpoint"}
    if finding.rule_id == "MEMORY_REGION_WITH_SUSPICIOUS_COMMAND":
        return {"memory_region", "suspicious_command"}
    if finding.rule_id == "MEMORY_REGION_WITH_SUSPICIOUS_MODULE":
        if microsoft_module_reputation(finding):
            return {"memory_region", "module_context"}
        return {"memory_region", "suspicious_module"}
    if finding.rule_id in NETWORK_CORRELATION_RULE_IDS:
        return {"network_endpoint"}
    if finding.rule_id in COMMAND_CORRELATION_RULE_IDS:
        return {"suspicious_command"}
    if finding.rule_id in MODULE_CORRELATION_RULE_IDS:
        if microsoft_module_reputation(finding):
            return {"module_context"}
        return {"suspicious_module"}
    if finding.rule_id in YARA_RULE_IDS or finding.artifact_type == "yara_matches":
        return {"yara_match"}
    if finding.rule_id in MEMORY_REGION_RULE_IDS or finding.artifact_type == "memory_region_artifacts":
        return {"memory_region"}
    return {finding.rule_id.lower()}


def count_unique_values(components: list[FindingDraft], group_name: str) -> int:
    values = set()
    for component in components:
        extra_data = component.extra_data or {}
        linked_artifacts = extra_data.get("linked_artifacts") or {}
        groups = evidence_groups_for_finding(component)
        if group_name not in groups:
            continue
        if group_name == "memory_region":
            values.add((extra_data.get("pid"), extra_data.get("start_address"), extra_data.get("end_address")))
        elif group_name == "network_endpoint":
            values.add((linked_artifacts.get("remote_address") or extra_data.get("remote_address"), linked_artifacts.get("remote_port") or extra_data.get("remote_port")))
        elif group_name == "yara_match":
            values.add((extra_data.get("rule_name"), extra_data.get("target_identifier"), extra_data.get("pid")))
    return len({value for value in values if any(part is not None for part in value)})


def yara_rule_summary(components: list[FindingDraft]) -> tuple[list[str], int]:
    grouped: dict[tuple, int] = {}
    rule_names = set()
    for component in components:
        if "yara_match" not in evidence_groups_for_finding(component):
            continue
        extra_data = component.extra_data or {}
        rule_name = extra_data.get("rule_name")
        target_identifier = extra_data.get("target_identifier")
        pid = extra_data.get("pid")
        key = (rule_name, target_identifier, pid, normalize_text(extra_data.get("process_name")))
        if rule_name:
            rule_names.add(str(rule_name))
        match_count = extra_data.get("yara_match_count")
        try:
            normalized_count = int(match_count)
        except (TypeError, ValueError):
            normalized_count = 1
        grouped[key] = max(grouped.get(key, 0), normalized_count)
    return sorted(rule_names), sum(grouped.values())


def extra_flag_enabled(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    return str(value).strip().lower() in {"true", "yes", "1"}


def has_high_confidence_yara(components: list[FindingDraft]) -> bool:
    for component in components:
        if "yara_match" not in evidence_groups_for_finding(component):
            continue
        extra_data = component.extra_data or {}
        confidence = normalize_text(extra_data.get("confidence"))
        noisy = extra_flag_enabled(extra_data.get("noisy", False))
        severity = normalize_text(extra_data.get("triage_severity")) or normalize_text(component.severity)
        if confidence in {"high", "confirmed"} and not noisy and severity in {"high", "critical"}:
            return True
    return False


def has_malware_specific_yara(components: list[FindingDraft]) -> bool:
    for component in components:
        if "yara_match" not in evidence_groups_for_finding(component):
            continue
        extra_data = component.extra_data or {}
        family = normalize_text(extra_data.get("malware_family") or extra_data.get("family"))
        category = normalize_text(extra_data.get("rule_category") or extra_data.get("category"))
        description = normalize_text(extra_data.get("description"))
        rule_name = normalize_text(extra_data.get("rule_name"))
        text = " ".join(value for value in [family, category, description, rule_name] if value)
        if family and family not in {"generic", "unknown", "n/a", "none"}:
            return True
        if any(term in text for term in ["cobalt", "beacon", "malware", "trojan", "loader", "backdoor", "ransom", "mimikatz"]):
            return True
    return False


def has_very_high_confidence_yara(components: list[FindingDraft]) -> bool:
    for component in components:
        if "yara_match" not in evidence_groups_for_finding(component):
            continue
        extra_data = component.extra_data or {}
        confidence = normalize_text(extra_data.get("confidence"))
        severity = normalize_text(extra_data.get("triage_severity")) or normalize_text(component.severity)
        noisy = extra_flag_enabled(extra_data.get("noisy", False))
        if confidence in {"high", "confirmed"} and severity == "critical" and not noisy and has_malware_specific_yara([component]):
            return True
    return False


def has_correlated_yara_evidence(evidence_groups: set[str]) -> bool:
    return "yara_match" in evidence_groups and bool(
        evidence_groups & {"memory_region", "network_endpoint", "suspicious_command", "suspicious_module", "module_context"}
    )


def has_benign_context_only(components: list[FindingDraft], evidence_groups: set[str]) -> bool:
    if not components:
        return False
    benign_components = [
        component
        for component in components
        if (component.extra_data or {}).get("finding_intent") == "benign_context"
        or (component.extra_data or {}).get("detection_confidence") == "context_only"
    ]
    if not benign_components:
        return False
    strong_groups = {"network_endpoint", "suspicious_command", "suspicious_module"}
    return not bool(evidence_groups & strong_groups) and not has_malware_specific_yara(components)


def recommendation_for_process_summary(confidence: str) -> str:
    if confidence == "probable_malware":
        return (
            "Treat this as a priority investigation candidate: validate containment needs, hunt for related telemetry, "
            "and confirm the memory, YARA, network, and command-line evidence before declaring compromise."
        )
    if confidence == "context_only":
        return (
            "Review as low-priority context unless additional malware-specific YARA, network, command-line, or memory "
            "correlation appears. Do not treat this context alone as a containment trigger."
        )
    return (
        "Validate this suspicious triage signal by correlating the process, memory regions, YARA metadata, command line, "
        "modules, and network evidence."
    )


def score_by_independent_evidence_groups(components: list[FindingDraft]) -> tuple[int, set[str]]:
    group_scores: dict[str, int] = {}
    evidence_groups = set()
    for component in components:
        groups = evidence_groups_for_finding(component)
        evidence_groups.update(groups)
        for group in groups:
            group_scores[group] = max(group_scores.get(group, 0), component.score)
    return sum(group_scores.values()), evidence_groups


def unique_components(components: list[FindingDraft]) -> list[FindingDraft]:
    selected = []
    seen = set()
    for component in components:
        key = component_key(component)
        if key in seen:
            continue
        seen.add(key)
        selected.append(component)
    return selected


def process_identity(pid, process_name) -> str:
    if process_name and pid is not None:
        return f"{process_name} (PID {pid})"
    if process_name:
        return str(process_name)
    if pid is not None:
        return f"PID {pid}"
    return "unknown process"


def build_process_risk_summaries(
    findings: list[FindingDraft],
    scoring_config: dict,
    artifacts: dict[str, list[dict]] | None = None,
) -> list[FindingDraft]:
    resolver = build_process_identity_resolver(artifacts)
    grouped: dict[tuple, list[FindingDraft]] = defaultdict(list)
    for finding in findings:
        if finding.category == "process_risk_summary":
            continue
        resolved_finding = finding_with_resolved_identity(finding, resolver)
        key = process_key_from_finding(resolved_finding)
        if key is not None:
            grouped[key].append(resolved_finding)

    summaries = []
    max_components = (
        scoring_config.get("aggregation", {})
        .get("process", {})
        .get("max_findings_per_process", 20)
    )
    for process_key, components in grouped.items():
        deduped = unique_components(components)
        if len(deduped) < 2:
            continue
        selected = deduped[:max_components]
        total_score, evidence_groups = score_by_independent_evidence_groups(selected)
        if evidence_groups == {"yara_match"}:
            total_score = min(total_score, 5)
        elif evidence_groups == {"network_endpoint"}:
            total_score = min(total_score, 5)
        elif evidence_groups <= {"suspicious_module"}:
            total_score = min(total_score, 5)
        elif evidence_groups <= {"module_context"}:
            total_score = min(total_score, 4)
        elif evidence_groups <= {"suspicious_module", "module_context"}:
            total_score = min(total_score, 5)
        severity = severity_for_score(total_score, scoring_config)
        has_memory = "memory_region" in evidence_groups
        has_yara = "yara_match" in evidence_groups
        has_network = "network_endpoint" in evidence_groups
        has_command = "suspicious_command" in evidence_groups
        has_strong_yara = has_high_confidence_yara(selected) and has_malware_specific_yara(selected)
        if severity == "critical" and len(evidence_groups) < 2:
            severity = "high"
        if severity == "critical" and evidence_groups <= {"memory_region", "module_context"}:
            severity = "high"
        if severity == "critical":
            critical_allowed = (
                (has_memory and has_yara and has_strong_yara)
                or (has_memory and has_yara and has_network)
                or (has_memory and has_yara and has_command)
                or has_very_high_confidence_yara(selected)
            )
            if not critical_allowed:
                severity = "high"
        if severity in {"high", "critical"} and has_benign_context_only(selected, evidence_groups):
            severity = "medium"
        first = selected[0]
        first_extra = first.extra_data or {}
        pid = first_extra.get("pid") or next(
            ((component.extra_data or {}).get("pid") for component in selected if (component.extra_data or {}).get("pid") is not None),
            None,
        )
        process_name = first_extra.get("process_name") or next(
            (
                (component.extra_data or {}).get("process_name")
                for component in selected
                if (component.extra_data or {}).get("process_name")
            ),
            None,
        )
        image_path = first_extra.get("image_path") or next(
            ((component.extra_data or {}).get("image_path") for component in selected if (component.extra_data or {}).get("image_path")),
            None,
        )
        command_line = first_extra.get("command_line") or next(
            ((component.extra_data or {}).get("command_line") for component in selected if (component.extra_data or {}).get("command_line")),
            None,
        )
        ppid = first_extra.get("ppid") or next(
            ((component.extra_data or {}).get("ppid") for component in selected if (component.extra_data or {}).get("ppid") is not None),
            None,
        )
        parent_process_name = first_extra.get("parent_process_name") or next(
            ((component.extra_data or {}).get("parent_process_name") for component in selected if (component.extra_data or {}).get("parent_process_name")),
            None,
        )
        component_rule_ids = sorted({component.rule_id for component in selected})
        component_categories = sorted({component.category for component in selected})
        identity = process_identity(pid, process_name)
        unique_component_count = len(selected)
        memory_region_count = count_unique_values(selected, "memory_region")
        network_endpoint_count = count_unique_values(selected, "network_endpoint")
        yara_match_count = count_unique_values(selected, "yara_match")
        yara_rules, raw_yara_match_count = yara_rule_summary(selected)
        correlated_yara = has_correlated_yara_evidence(evidence_groups)
        very_high_yara = has_very_high_confidence_yara(selected)
        confidence = "probable_malware" if severity in {"critical", "high"} and (
            (correlated_yara and has_malware_specific_yara(selected))
            or ("memory_region" in evidence_groups and bool(evidence_groups & {"network_endpoint", "suspicious_command"}))
            or very_high_yara
        ) else "suspicious"
        if has_benign_context_only(selected, evidence_groups):
            confidence = "context_only"
        elif evidence_groups <= {"module_context"}:
            confidence = "context_only"
        summaries.append(
            FindingDraft(
                analysis_job_id=first.analysis_job_id,
                evidence_id=first.evidence_id,
                plugin_result_id=None,
                os_family=first.os_family,
                os_scope="all",
                source_plugin=None,
                rule_id="PROCESS_RISK_SUMMARY",
                rule_name="Process risk summary",
                category="process_risk_summary",
                severity=severity,
                score=total_score,
                title=f"{severity.title()} risk process: {identity}",
                description=f"Aggregated process-level risk for {identity} based on {', '.join(component_rule_ids)}.",
                artifact_type="process",
                artifact_id=":".join(str(part) for part in process_key[1:]),
                recommendation=recommendation_for_process_summary(confidence),
                extra_data={
                    "pid": pid,
                    "process_name": process_name,
                    "image_path": image_path,
                    "command_line": command_line,
                    "ppid": ppid,
                    "parent_process_name": parent_process_name,
                    "total_score": total_score,
                    "unique_component_count": unique_component_count,
                    "component_finding_ids": [str(component.id) for component in selected],
                    "component_rule_ids": component_rule_ids,
                    "component_categories": component_categories,
                    "evidence_groups": sorted(evidence_groups),
                    "memory_region_count": memory_region_count,
                    "network_endpoint_count": network_endpoint_count,
                    "yara_rule_count": yara_match_count,
                    "yara_match_count": yara_match_count,
                    "yara_raw_match_count": raw_yara_match_count,
                    "yara_rules": yara_rules,
                    "finding_intent": "detection" if confidence == "probable_malware" else "suspicious_triage",
                    "detection_confidence": confidence,
                },
            )
        )
    return summaries
