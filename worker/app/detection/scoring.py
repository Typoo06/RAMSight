# Process-level risk aggregation helpers.

from collections import defaultdict

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
    image_path = normalize_path(extra_data.get("image_path"))
    if pid is not None and process_name and image_path:
        return "pid_name_path", pid, process_name, image_path
    if pid is not None and process_name:
        return "pid_name", pid, process_name
    if pid is not None:
        return "pid", pid
    if process_name:
        return "name", process_name
    return None


def component_key(finding: FindingDraft) -> tuple:
    extra_data = finding.extra_data or {}
    linked_artifacts = extra_data.get("linked_artifacts") or {}
    if finding.rule_id in YARA_RULE_IDS or finding.artifact_type == "yara_matches":
        return (
            "yara_match",
            extra_data.get("pid"),
            normalize_text(extra_data.get("process_name")),
            extra_data.get("target_identifier"),
            normalize_text(extra_data.get("rule_name")),
            finding.source_plugin,
        )
    return (
        finding.rule_id,
        finding.category,
        extra_data.get("pid"),
        normalize_text(extra_data.get("process_name")),
        normalize_path(extra_data.get("image_path")),
        normalize_path(extra_data.get("module_path")),
        extra_data.get("start_address"),
        extra_data.get("end_address"),
        linked_artifacts.get("remote_address") or extra_data.get("remote_address"),
        linked_artifacts.get("remote_port") or extra_data.get("remote_port"),
        normalize_text(linked_artifacts.get("command_excerpt") or extra_data.get("command_excerpt")),
        normalize_path(linked_artifacts.get("module_path") or extra_data.get("module_path")),
        extra_data.get("rule_name"),
        extra_data.get("offset"),
    )


def evidence_groups_for_finding(finding: FindingDraft) -> set[str]:
    if finding.rule_id in NETWORK_CORRELATION_RULE_IDS:
        return {"network_endpoint"}
    if finding.rule_id in COMMAND_CORRELATION_RULE_IDS:
        return {"suspicious_command"}
    if finding.rule_id in MODULE_CORRELATION_RULE_IDS:
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


def build_process_risk_summaries(findings: list[FindingDraft], scoring_config: dict) -> list[FindingDraft]:
    grouped: dict[tuple, list[FindingDraft]] = defaultdict(list)
    for finding in findings:
        if finding.category == "process_risk_summary":
            continue
        key = process_key_from_finding(finding)
        if key is not None:
            grouped[key].append(finding)

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
        severity = severity_for_score(total_score, scoring_config)
        if severity == "critical" and len(evidence_groups) < 2:
            severity = "high"
        if severity == "critical" and "yara_match" in evidence_groups:
            has_memory = "memory_region" in evidence_groups
            has_strong_context = bool(evidence_groups & {"network_endpoint", "suspicious_command", "suspicious_module"})
            if not (has_memory and has_strong_context):
                severity = "high"
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
        component_rule_ids = sorted({component.rule_id for component in selected})
        component_categories = sorted({component.category for component in selected})
        identity = process_identity(pid, process_name)
        unique_component_count = len(selected)
        memory_region_count = count_unique_values(selected, "memory_region")
        network_endpoint_count = count_unique_values(selected, "network_endpoint")
        yara_match_count = count_unique_values(selected, "yara_match")
        yara_rules, raw_yara_match_count = yara_rule_summary(selected)
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
                recommendation="Prioritize this process for analyst review and correlate all component findings.",
                extra_data={
                    "pid": pid,
                    "process_name": process_name,
                    "image_path": image_path,
                    "total_score": total_score,
                    "unique_component_count": unique_component_count,
                    "component_finding_ids": [str(component.id) for component in selected],
                    "component_rule_ids": component_rule_ids,
                    "component_categories": component_categories,
                    "evidence_groups": sorted(evidence_groups),
                    "memory_region_count": memory_region_count,
                    "network_endpoint_count": network_endpoint_count,
                    "yara_rule_count": yara_match_count,
                    "yara_match_count": raw_yara_match_count,
                    "yara_rules": yara_rules,
                },
            )
        )
    return summaries
