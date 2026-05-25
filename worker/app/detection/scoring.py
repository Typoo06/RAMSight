# Process-level risk aggregation helpers.

from collections import defaultdict

from app.detection.rules import FindingDraft
from app.parsers.common import is_placeholder_value


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
    return (
        finding.rule_id,
        finding.category,
        extra_data.get("pid"),
        normalize_text(extra_data.get("process_name")),
        normalize_path(extra_data.get("image_path")),
        normalize_path(extra_data.get("module_path")),
        extra_data.get("start_address"),
        extra_data.get("end_address"),
        extra_data.get("remote_address"),
        extra_data.get("remote_port"),
    )


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
        total_score = sum(component.score for component in selected)
        severity = severity_for_score(total_score, scoring_config)
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
                    "component_finding_ids": [str(component.id) for component in selected],
                    "component_rule_ids": component_rule_ids,
                    "component_categories": component_categories,
                },
            )
        )
    return summaries
