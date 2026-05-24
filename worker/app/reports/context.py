# Report context building and section shaping.

from datetime import datetime, timezone
from typing import Iterable

from app.reports.recommendations import generate_recommendations

TOP_FINDINGS_LIMIT = 20
SECTION_ROW_LIMIT = 50
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def row_dict(row: dict | None) -> dict:
    return dict(row or {})


def limited(rows: Iterable[dict], limit: int = SECTION_ROW_LIMIT) -> list[dict]:
    return list(rows)[:limit]


def finding_sort_key(finding: dict) -> tuple[int, int]:
    severity = str(finding.get("severity") or "low").lower()
    return SEVERITY_RANK.get(severity, 0), int(finding.get("score") or 0)


def top_findings(findings: list[dict], limit: int = TOP_FINDINGS_LIMIT) -> list[dict]:
    return sorted(findings, key=finding_sort_key, reverse=True)[:limit]


def count_artifacts(artifacts: dict[str, list[dict]]) -> int:
    return sum(len(records) for records in artifacts.values())


def build_summary(plugin_results: list[dict], artifacts: dict[str, list[dict]], risk_findings: list[dict], iocs: list[dict]) -> dict:
    completed = [plugin for plugin in plugin_results if plugin.get("status") == "completed"]
    failed = [plugin for plugin in plugin_results if plugin.get("status") == "failed"]
    return {
        "total_plugin_results": len(plugin_results),
        "completed_plugins": len(completed),
        "failed_plugins": len(failed),
        "total_parsed_artifacts": count_artifacts(artifacts),
        "total_risk_findings": len(risk_findings),
        "total_ioc_records": len(iocs),
    }


def suspicious_modules(modules: list[dict], findings: list[dict]) -> list[dict]:
    finding_artifact_ids = {finding.get("artifact_id") for finding in findings if finding.get("artifact_type") == "module_artifacts"}
    selected = []
    for module in modules:
        path = str(module.get("module_path") or "").lower().replace("\\", "/")
        if str(module.get("id")) in finding_artifact_ids or any(fragment in path for fragment in ["/temp/", "/appdata/", "/users/public/", "/tmp/"]):
            selected.append(module)
    return limited(selected)


def build_report_context(
    case: dict,
    evidence: dict,
    analysis_job: dict,
    plugin_results: list[dict],
    artifacts: dict[str, list[dict]],
    risk_findings: list[dict],
    iocs: list[dict],
    analyst_notes: list[dict] | None = None,
    generated_at: datetime | None = None,
) -> dict:
    context = {
        "product_name": "RAMSight",
        "report_title": "RAMSight Technical Analysis Report",
        "report_type": "technical",
        "case": row_dict(case),
        "evidence": row_dict(evidence),
        "analysis_job": row_dict(analysis_job),
        "plugin_results": limited(plugin_results, 100),
        "risk_findings": risk_findings,
        "top_findings": top_findings(risk_findings),
        "process_risk_summaries": limited([finding for finding in risk_findings if finding.get("category") == "process_risk_summary"]),
        "process_artifacts": limited(artifacts.get("process_artifacts", [])),
        "network_indicators": limited(artifacts.get("network_artifacts", [])),
        "module_artifacts": suspicious_modules(artifacts.get("module_artifacts", []), risk_findings),
        "memory_regions": limited(artifacts.get("memory_region_artifacts", [])),
        "command_artifacts": limited(artifacts.get("command_artifacts", [])),
        "yara_matches": limited(artifacts.get("yara_matches", [])),
        "iocs": limited(iocs, 100),
        "analyst_notes": limited(analyst_notes or [], 20),
        "generated_at": generated_at or utc_now(),
    }
    context["summary"] = build_summary(plugin_results, artifacts, risk_findings, iocs)
    context["recommendations"] = generate_recommendations(context)
    return context
