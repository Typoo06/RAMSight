# Report context building and section shaping.

from datetime import datetime, timezone
from typing import Iterable

from app.reports.recommendations import generate_recommendations

TOP_FINDINGS_LIMIT = 20
SECTION_ROW_LIMIT = 50
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
YARA_PLUGIN_NAMES = {"windows.vadyarascan", "yarascan", "linux.vmayarascan"}


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



def _plugin_name(plugin: dict) -> str:
    return str(plugin.get("plugin_name") or plugin.get("source_plugin") or "")


def _extra_data(plugin: dict) -> dict:
    extra_data = plugin.get("extra_data")
    return extra_data if isinstance(extra_data, dict) else {}


def _is_yara_plugin_result(plugin: dict) -> bool:
    name = _plugin_name(plugin)
    extra_data = _extra_data(plugin)
    return name in YARA_PLUGIN_NAMES or bool(extra_data.get("is_yara_plugin"))


def _timeout_seconds(plugin: dict) -> int | None:
    value = _extra_data(plugin).get("timeout_seconds")
    return value if isinstance(value, int) else None


def _is_timeout(plugin: dict) -> bool:
    extra_data = _extra_data(plugin)
    error_message = str(plugin.get("error_message") or "").lower()
    return bool(extra_data.get("timed_out")) or extra_data.get("timeout_reason") == "plugin_timeout" or "timed out" in error_message


def _yara_status_message(status: str, plugin: dict | None = None) -> str:
    if status == "not_selected":
        return "YARA was not selected for this analysis profile."
    if status == "unavailable":
        return "YARA was requested, but plugin status was not available when this report was generated."
    if plugin is None:
        return "YARA status is not available for this analysis profile."

    plugin_name = _plugin_name(plugin) or "YARA plugin"
    timeout = _timeout_seconds(plugin)
    error_message = plugin.get("error_message")
    if status == "failed_timeout":
        if timeout is not None:
            return f"YARA scanning was selected but {plugin_name} timed out after {timeout} seconds."
        return f"YARA scanning was selected but {plugin_name} timed out."
    if status == "failed":
        if error_message:
            return f"YARA scanning was selected but {plugin_name} failed: {error_message}"
        return f"YARA scanning was selected but {plugin_name} failed."
    if status == "skipped":
        if error_message:
            return f"YARA scanning was selected but {plugin_name} was skipped: {error_message}"
        return f"YARA scanning was selected but {plugin_name} was skipped."
    if status == "completed_with_matches":
        return "YARA scanning completed and YARA match artifacts are listed below."
    if status == "completed_no_matches":
        return "YARA scanning completed; no YARA match artifacts were recorded."
    return "YARA scanning is pending or running; this report may have been generated before YARA status was final."


def build_yara_status(analysis_job: dict, plugin_results: list[dict], yara_matches: list[dict]) -> dict:
    yara_plugins = [plugin for plugin in plugin_results if _is_yara_plugin_result(plugin)]
    plugin_profile = str(analysis_job.get("plugin_profile") or "").strip().lower()

    if not yara_plugins:
        status = "unavailable" if plugin_profile == "windows_memory_yara" else "not_selected"
        return {"selected": status != "not_selected", "status": status, "message": _yara_status_message(status)}

    timed_out = next((plugin for plugin in yara_plugins if str(plugin.get("status") or "").lower() == "failed" and _is_timeout(plugin)), None)
    if timed_out is not None:
        return {
            "selected": True,
            "status": "failed_timeout",
            "plugin_name": _plugin_name(timed_out),
            "timeout_seconds": _timeout_seconds(timed_out),
            "message": _yara_status_message("failed_timeout", timed_out),
        }

    failed = next((plugin for plugin in yara_plugins if str(plugin.get("status") or "").lower() == "failed"), None)
    if failed is not None:
        return {"selected": True, "status": "failed", "plugin_name": _plugin_name(failed), "message": _yara_status_message("failed", failed)}

    skipped = next((plugin for plugin in yara_plugins if str(plugin.get("status") or "").lower() == "skipped"), None)
    if skipped is not None:
        return {"selected": True, "status": "skipped", "plugin_name": _plugin_name(skipped), "message": _yara_status_message("skipped", skipped)}

    completed = next((plugin for plugin in yara_plugins if str(plugin.get("status") or "").lower() == "completed"), None)
    if completed is not None:
        status = "completed_with_matches" if yara_matches else "completed_no_matches"
        return {"selected": True, "status": status, "plugin_name": _plugin_name(completed), "message": _yara_status_message(status, completed)}

    plugin = yara_plugins[0]
    return {"selected": True, "status": str(plugin.get("status") or "unknown"), "plugin_name": _plugin_name(plugin), "message": _yara_status_message("running", plugin)}


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
    context["yara_status"] = build_yara_status(context["analysis_job"], context["plugin_results"], context["yara_matches"])
    context["recommendations"] = generate_recommendations(context)
    return context
