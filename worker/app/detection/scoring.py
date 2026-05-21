# Process-level risk aggregation helpers.

from collections import defaultdict

from app.detection.rules import FindingDraft


def severity_for_score(score: int, scoring_config: dict) -> str:
    for severity, bounds in (scoring_config.get("risk_levels") or {}).items():
        minimum = bounds.get("min", 0)
        maximum = bounds.get("max")
        if score >= minimum and (maximum is None or score <= maximum):
            return str(severity)
    return "critical" if score >= 13 else "low"


def process_key_from_finding(finding: FindingDraft) -> tuple | None:
    extra_data = finding.extra_data or {}
    pid = extra_data.get("pid")
    process_name = extra_data.get("process_name")
    if pid is not None:
        return "pid", pid
    if process_name:
        return "name", str(process_name).lower()
    return None


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
    for (_key_type, process_key), components in grouped.items():
        if len(components) < 2:
            continue
        selected = components[:max_components]
        total_score = sum(component.score for component in selected)
        severity = severity_for_score(total_score, scoring_config)
        first = selected[0]
        first_extra = first.extra_data or {}
        pid = first_extra.get("pid") if _key_type == "pid" else None
        process_name = first_extra.get("process_name") or next(
            (
                (component.extra_data or {}).get("process_name")
                for component in selected
                if (component.extra_data or {}).get("process_name")
            ),
            None,
        )
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
                title="Process risk summary",
                description="Aggregated process-level risk based on related detection findings.",
                artifact_type="process",
                artifact_id=str(process_key),
                recommendation="Prioritize this process for analyst review and correlate all component findings.",
                extra_data={
                    "pid": pid,
                    "process_name": process_name,
                    "total_score": total_score,
                    "component_finding_ids": [str(component.id) for component in selected],
                    "component_rule_ids": [component.rule_id for component in selected],
                },
            )
        )
    return summaries
