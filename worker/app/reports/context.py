# Report context building and section shaping.

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import ipaddress
from typing import Iterable
import re

from app.detection.path_reputation import known_microsoft_appdata_path, normalize_windows_path
from app.parsers.common import is_path_like
from app.reports.recommendations import generate_recommendations

TOP_FINDINGS_LIMIT = 20
TOP_PROCESS_LIMIT = 10
SECTION_ROW_LIMIT = 50
NETWORK_DISPLAY_LIMIT = 20
MODULE_DISPLAY_LIMIT = 20
IOC_REPRESENTATIVE_LIMIT = 5
YARA_REPRESENTATIVE_LIMIT = 5
ERROR_SUMMARY_LIMIT = 180
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
YARA_PLUGIN_NAMES = {"windows.vadyarascan", "yarascan", "linux.vmayarascan"}
PATH_LIKE_RE = re.compile(r"((?:/[^\s:;'\"]+){2,}|[A-Za-z]:\\[^\s:;'\"]+)")
PID_RE = re.compile(r"\b(?:pid\s*)?(\d+)\b", re.IGNORECASE)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def row_dict(row: dict | None) -> dict:
    return dict(row or {})


def limited(rows: Iterable[dict], limit: int = SECTION_ROW_LIMIT) -> list[dict]:
    return list(rows)[:limit]


def _extra_data(row: dict | None) -> dict:
    extra_data = (row or {}).get("extra_data")
    return extra_data if isinstance(extra_data, dict) else {}


def _linked_artifacts(row: dict | None) -> dict:
    linked = _extra_data(row).get("linked_artifacts")
    return linked if isinstance(linked, dict) else {}


def _text(value, default: str = "N/A") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def _raw_text(value) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _list_values(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [_text(item) for item in value if _raw_text(item)]
    text = _raw_text(value)
    return [text] if text else []


def _int_value(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _severity(value) -> str:
    text = str(value or "low").lower()
    return text if text in SEVERITY_RANK else "low"


def _severity_rank(value) -> int:
    return SEVERITY_RANK.get(_severity(value), 0)


def _is_high_priority(finding: dict) -> bool:
    return _severity(finding.get("severity")) in {"critical", "high"}


def _process_identity(process_name, pid) -> str:
    name = _raw_text(process_name)
    if name and pid is not None:
        return f"{name} (PID {pid})"
    if name:
        return name
    if pid is not None:
        return f"PID {pid}"
    return "N/A"


def _pid_from_text(value) -> int | None:
    text = _raw_text(value)
    if not text:
        return None
    match = PID_RE.search(text)
    return int(match.group(1)) if match else None


def _pid_key(value) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def _safe_error_summary(value) -> str:
    text = _raw_text(value)
    if not text:
        return "N/A"
    text = " ".join(text.split())
    text = PATH_LIKE_RE.sub("[path omitted]", text)
    if len(text) > ERROR_SUMMARY_LIMIT:
        return f"{text[:ERROR_SUMMARY_LIMIT].rstrip()}..."
    return text


def _display_offset(match: dict) -> str:
    extra = _extra_data(match)
    raw_offset = extra.get("offset_raw")
    if raw_offset is not None:
        return _text(raw_offset)
    offset = match.get("offset")
    if isinstance(offset, int):
        return hex(offset)
    return _text(offset)


def finding_sort_key(finding: dict) -> tuple[int, int]:
    return _severity_rank(finding.get("severity")), _int_value(finding.get("score"))


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



def _artifact_ids_by_type(findings: list[dict], artifact_type: str) -> set[str]:
    ids = set()
    for finding in findings:
        if finding.get("artifact_type") != artifact_type:
            continue
        artifact_id = finding.get("artifact_id")
        if artifact_id is not None:
            ids.add(str(artifact_id))
    return ids


def _is_public_ip(value) -> bool:
    text = _raw_text(value)
    if not text:
        return False
    cleaned = text.strip("[]")
    if "%" in cleaned:
        cleaned = cleaned.split("%", 1)[0]
    try:
        address = ipaddress.ip_address(cleaned)
    except ValueError:
        return False
    return address.is_global


def _is_empty_or_wildcard_address(value) -> bool:
    text = (_raw_text(value) or "").strip().lower()
    return text in {"", "*", "0.0.0.0", "::", "::0", "[::]", "0", "none", "n/a"}


def _network_artifact_linked(row: dict, findings: list[dict], iocs: list[dict]) -> bool:
    row_id = row.get("id")
    if row_id is not None and str(row_id) in _artifact_ids_by_type(findings, "network_artifacts"):
        return True

    remote_address = _raw_text(row.get("remote_address"))
    remote_port = row.get("remote_port")
    pid = _pid_key(row.get("pid"))
    endpoint = _network_endpoint(row)
    for ioc in iocs:
        ioc_value = _raw_text(ioc.get("value"))
        extra = _extra_data(ioc)
        if endpoint and ioc_value == endpoint:
            return True
        if remote_address and ioc_value == remote_address:
            return True
        if remote_address and extra.get("remote_address") == remote_address and (remote_port is None or extra.get("remote_port") == remote_port):
            return True
        if pid and _pid_key(extra.get("pid")) == pid and remote_address and extra.get("remote_address") == remote_address:
            return True
    return False


def _network_display_score(row: dict, findings: list[dict], iocs: list[dict]) -> tuple[int, int]:
    state = str(row.get("state") or "").strip().lower()
    remote_address = row.get("remote_address")
    remote_port = row.get("remote_port")
    score = 0
    if _is_public_ip(remote_address):
        score += 60
    if remote_port is not None and not _is_empty_or_wildcard_address(remote_address):
        score += 15
    if state in {"established", "syn_sent", "syn_recv", "close_wait", "time_wait"}:
        score += 15
    if _network_artifact_linked(row, findings, iocs):
        score += 30
    if state == "listening":
        score -= 25
    if _is_empty_or_wildcard_address(remote_address) or remote_port is None:
        score -= 15
    return score, _int_value(row.get("pid"), -1)


def _network_dedupe_key(row: dict) -> tuple:
    state = str(row.get("state") or "").strip().lower()
    remote_address = _raw_text(row.get("remote_address"))
    remote_port = row.get("remote_port")
    protocol = str(row.get("protocol") or "").strip().lower()
    local_address = _raw_text(row.get("local_address"))
    local_port = row.get("local_port")
    pid = _pid_key(row.get("pid"))
    process_name = str(row.get("process_name") or "").strip().lower()
    if state == "listening" and (_is_empty_or_wildcard_address(remote_address) or remote_port is None):
        return ("listener", protocol, local_port, pid, process_name)
    return (
        protocol,
        local_address,
        local_port,
        remote_address,
        remote_port,
        state,
        pid,
        process_name,
        row.get("source_plugin"),
    )


def _endpoint(address, port) -> str:
    text = _raw_text(address)
    if not text:
        return "N/A"
    return f"{text}:{port}" if port is not None else text


def _network_display_reason(row: dict, linked: bool) -> str:
    state = str(row.get("state") or "").strip().lower()
    if _is_public_ip(row.get("remote_address")):
        return "Public remote endpoint"
    if linked:
        return "Linked to finding or IOC context"
    if state == "listening":
        return "Listening service socket shown as context"
    return "Network artifact context"


def build_network_display(network_rows: list[dict], findings: list[dict], iocs: list[dict], limit: int = NETWORK_DISPLAY_LIMIT) -> dict:
    buckets: dict[tuple, dict] = {}
    for row in network_rows:
        key = _network_dedupe_key(row)
        score, pid_score = _network_display_score(row, findings, iocs)
        linked = _network_artifact_linked(row, findings, iocs)
        bucket = buckets.get(key)
        if bucket is None:
            buckets[key] = {"row": row, "count": 1, "sort_key": (score, pid_score), "linked": linked}
            continue
        bucket["count"] += 1
        bucket["linked"] = bucket["linked"] or linked
        if (score, pid_score) > bucket["sort_key"]:
            bucket["row"] = row
            bucket["sort_key"] = (score, pid_score)

    sorted_buckets = sorted(buckets.values(), key=lambda item: item["sort_key"], reverse=True)
    rows = []
    for bucket in sorted_buckets[:limit]:
        row = bucket["row"]
        rows.append(
            {
                "protocol": _text(row.get("protocol"), ""),
                "local_endpoint": _endpoint(row.get("local_address"), row.get("local_port")),
                "remote_endpoint": _endpoint(row.get("remote_address"), row.get("remote_port")),
                "state": _text(row.get("state"), ""),
                "pid": _text(row.get("pid"), ""),
                "process_name": _text(row.get("process_name"), ""),
                "source_plugin": _text(row.get("source_plugin"), ""),
                "reason": _network_display_reason(row, bucket["linked"]),
                "similar_count": bucket["count"],
            }
        )
    return {
        "rows": rows,
        "total_count": len(network_rows),
        "displayed_count": len(rows),
        "omitted_count": max(len(network_rows) - len(rows), 0),
        "note": "This table is capped for readability. Full normalized artifacts remain available through the platform/API.",
    }


def _artifact_os_family(row: dict, path: str | None = None) -> str:
    value = _raw_text(row.get("os_family"))
    if value:
        return value.lower()
    source_plugin = _raw_text(row.get("source_plugin"))
    if source_plugin and source_plugin.startswith("windows."):
        return "windows"
    if source_plugin and source_plugin.startswith("linux."):
        return "linux"
    if path and ("\\" in path or ":/" in path):
        return "windows"
    return "unknown"


def _is_user_writable_module_path(path: str, os_family: str) -> bool:
    if not is_path_like(path, os_family):
        return False
    normalized = normalize_windows_path(path) if os_family == "windows" else str(path or "").strip().lower()
    fragments = ["/appdata/", "/temp/", "/users/public/", "/tmp/", "/downloads/"]
    return any(fragment in normalized for fragment in fragments)


def _module_group_key(row: dict, classification_key: str, root_key: str) -> tuple:
    pid = _pid_key(row.get("pid"))
    process_name = str(row.get("process_name") or "").strip().lower()
    if classification_key == "known_microsoft_appdata":
        return (classification_key, pid, process_name, root_key)
    return (classification_key, pid, process_name, normalize_windows_path(row.get("module_path")))


def _module_display_row(row: dict, classification: str, note: str, count: int, source_plugins: set[str]) -> dict:
    return {
        "process_name": _text(row.get("process_name"), ""),
        "pid": _text(row.get("pid"), ""),
        "module_name": _text(row.get("module_name"), ""),
        "module_path": _text(row.get("module_path"), ""),
        "source_plugin": ", ".join(sorted(source_plugins)) if source_plugins else _text(row.get("source_plugin"), ""),
        "classification": classification,
        "context_note": note,
        "similar_count": count,
    }


def build_module_display(modules: list[dict], findings: list[dict], limit: int = MODULE_DISPLAY_LIMIT) -> dict:
    finding_artifact_ids = _artifact_ids_by_type(findings, "module_artifacts")
    buckets: dict[tuple, dict] = {}
    selected_count = 0
    known_context_count = 0
    suspicious_count = 0

    for module in modules:
        path = _raw_text(module.get("module_path"))
        if not path:
            continue
        os_family = _artifact_os_family(module, path)
        known = known_microsoft_appdata_path(path, os_family)
        linked = module.get("id") is not None and str(module.get("id")) in finding_artifact_ids
        user_writable = _is_user_writable_module_path(path, os_family)
        if not known and not linked and not user_writable:
            continue

        selected_count += 1
        if known:
            known_context_count += 1
            classification_key = "known_microsoft_appdata"
            classification = f"Known Microsoft AppData context ({known.app_name})"
            note = "Context only; not treated as standalone proof of compromise."
            root_key = known.normalized_root
            priority = 10 if linked else 0
        else:
            suspicious_count += 1
            classification_key = "unknown_user_writable"
            classification = "Unknown or user-writable module path"
            note = "Requires analyst review with process and memory-region context."
            root_key = normalize_windows_path(path)
            priority = 50 if linked else 35

        key = _module_group_key(module, classification_key, root_key)
        bucket = buckets.setdefault(
            key,
            {"row": module, "count": 0, "source_plugins": set(), "priority": priority, "classification": classification, "note": note},
        )
        bucket["count"] += 1
        bucket["priority"] = max(bucket["priority"], priority)
        source_plugin = _raw_text(module.get("source_plugin"))
        if source_plugin:
            bucket["source_plugins"].add(source_plugin)

    sorted_buckets = sorted(
        buckets.values(),
        key=lambda item: (item["priority"], item["count"], str(item["row"].get("process_name") or "").lower()),
        reverse=True,
    )
    rows = [
        _module_display_row(bucket["row"], bucket["classification"], bucket["note"], bucket["count"], bucket["source_plugins"])
        for bucket in sorted_buckets[:limit]
    ]
    return {
        "rows": rows,
        "total_count": len(modules),
        "selected_count": selected_count,
        "displayed_count": len(rows),
        "omitted_count": max(selected_count - len(rows), 0),
        "known_context_count": known_context_count,
        "suspicious_count": suspicious_count,
        "note": "Known Microsoft AppData module paths are shown as context and are not treated as standalone proof of compromise.",
    }


def _plugin_name(plugin: dict) -> str:
    return str(plugin.get("plugin_name") or plugin.get("source_plugin") or "")


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
    error_message = _safe_error_summary(plugin.get("error_message"))
    if status == "failed_timeout":
        if timeout is not None:
            return f"YARA scanning was selected but {plugin_name} timed out after {timeout} seconds."
        return f"YARA scanning was selected but {plugin_name} timed out."
    if status == "failed":
        if error_message != "N/A":
            return f"YARA scanning was selected but {plugin_name} failed: {error_message}"
        return f"YARA scanning was selected but {plugin_name} failed."
    if status == "skipped":
        if error_message != "N/A":
            return f"YARA scanning was selected but {plugin_name} was skipped: {error_message}"
        return f"YARA scanning was selected but {plugin_name} was skipped."
    if status == "completed_with_matches":
        return "YARA scanning completed and YARA match artifacts are summarized below."
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


def build_plugin_status_rows(plugin_results: list[dict]) -> list[dict]:
    rows = []
    for plugin in plugin_results:
        timeout = _timeout_seconds(plugin)
        timeout_status = "N/A"
        if _is_timeout(plugin):
            timeout_status = f"Timed out after {timeout} seconds" if timeout is not None else "Timed out"
        rows.append(
            {
                "plugin_name": _text(_plugin_name(plugin)),
                "status": _text(plugin.get("status")),
                "parsed_record_count": _text(plugin.get("parsed_record_count")),
                "duration_ms": _text(plugin.get("duration_ms")),
                "error_summary": _safe_error_summary(plugin.get("error_message")),
                "timeout_status": timeout_status,
                "is_yara_plugin": _is_yara_plugin_result(plugin),
                "raw_output_bucket": _text(plugin.get("raw_output_bucket")),
                "raw_output_key": _text(plugin.get("raw_output_key")),
                "parsed_output_bucket": _text(plugin.get("parsed_output_bucket")),
                "parsed_output_key": _text(plugin.get("parsed_output_key")),
            }
        )
    return rows


def _finding_pid_process(finding: dict) -> tuple[object | None, str | None]:
    extra = _extra_data(finding)
    linked = _linked_artifacts(finding)
    pid = extra.get("pid") if extra.get("pid") is not None else linked.get("pid")
    process_name = extra.get("process_name") or linked.get("process_name")
    return pid, _raw_text(process_name)


def _finding_context_parts(finding: dict) -> list[str]:
    extra = _extra_data(finding)
    linked = _linked_artifacts(finding)
    pid, process_name = _finding_pid_process(finding)
    parts = []
    if pid is not None:
        parts.append(f"PID {pid}")
    if process_name:
        parts.append(process_name)
    address_range = extra.get("address_range") or _address_range(extra) or _address_range(linked)
    if address_range:
        parts.append(f"region {address_range}")
    remote_address = linked.get("remote_address") or extra.get("remote_address")
    remote_port = linked.get("remote_port") or extra.get("remote_port")
    if remote_address:
        endpoint = f"{remote_address}:{remote_port}" if remote_port is not None else str(remote_address)
        parts.append(f"endpoint {endpoint}")
    rule_name = extra.get("rule_name")
    if rule_name:
        parts.append(f"YARA {rule_name}")
    module_name = linked.get("module_name") or extra.get("module_name")
    if module_name:
        parts.append(f"module {module_name}")
    return parts


def _address_range(row: dict) -> str | None:
    start = row.get("start_address")
    end = row.get("end_address")
    if start and end:
        return f"{start}-{end}"
    return _raw_text(row.get("address_range"))


def display_finding_row(finding: dict) -> dict:
    pid, process_name = _finding_pid_process(finding)
    return {
        "rule": _text(finding.get("rule_name") or finding.get("title")),
        "title": _text(finding.get("title") or finding.get("rule_name")),
        "severity": _severity(finding.get("severity")),
        "score": _text(finding.get("score")),
        "artifact_type": _text(finding.get("artifact_type")),
        "source_plugin": _text(finding.get("source_plugin")),
        "pid": _text(pid),
        "process_name": _text(process_name),
        "context_parts": _finding_context_parts(finding),
        "recommendation": _text(finding.get("recommendation"), "Review with surrounding forensic context."),
    }


def _display_finding_key(finding: dict) -> tuple:
    extra = _extra_data(finding)
    pid, process_name = _finding_pid_process(finding)
    return (
        finding.get("rule_id") or finding.get("rule_name"),
        pid,
        str(process_name or "").lower(),
        finding.get("artifact_type"),
        finding.get("category"),
        extra.get("address_range") or extra.get("start_address"),
        extra.get("end_address"),
    )


def build_display_top_findings(findings: list[dict], limit: int = TOP_FINDINGS_LIMIT) -> tuple[list[dict], int]:
    selected = []
    seen = set()
    omitted = 0
    display_candidates = [finding for finding in findings if finding.get("category") != "process_risk_summary"]
    for finding in sorted(display_candidates, key=finding_sort_key, reverse=True):
        key = _display_finding_key(finding)
        if key in seen or len(selected) >= limit:
            omitted += 1
            continue
        seen.add(key)
        selected.append(display_finding_row(finding))
    return selected, omitted


def _process_key(pid, process_name) -> tuple | None:
    if pid is not None and _raw_text(process_name):
        return "pid_name", str(pid), str(process_name).strip().lower()
    if pid is not None:
        return "pid", str(pid)
    if _raw_text(process_name):
        return "name", str(process_name).strip().lower()
    return None


def _process_group_sort_key(group: dict) -> tuple[int, int]:
    return _severity_rank(group.get("severity")), _int_value(group.get("score"))


def _format_process_group_from_summary(finding: dict) -> dict:
    extra = _extra_data(finding)
    pid = extra.get("pid")
    process_name = extra.get("process_name")
    evidence_groups = _list_values(extra.get("evidence_groups"))
    return {
        "finding_id": _text(finding.get("id")),
        "pid_raw": pid,
        "pid": _text(pid),
        "process_name": _text(process_name),
        "identity": _process_identity(process_name, pid),
        "severity": _severity(finding.get("severity")),
        "score": _text(finding.get("score") or extra.get("total_score")),
        "evidence_groups": evidence_groups,
        "component_rule_ids": _list_values(extra.get("component_rule_ids")),
        "memory_region_count": _int_value(extra.get("memory_region_count")),
        "network_endpoint_count": _int_value(extra.get("network_endpoint_count")),
        "yara_rule_count": _int_value(extra.get("yara_rule_count")),
        "yara_raw_match_count": _int_value(extra.get("yara_raw_match_count")),
        "recommendation": _text(finding.get("recommendation"), "Review this process with the component evidence."),
        "explanation": _text(finding.get("description"), "Process-level triage summary requiring analyst review."),
    }


def _format_process_group_from_findings(process_key: tuple, findings: list[dict]) -> dict:
    sorted_findings = sorted(findings, key=finding_sort_key, reverse=True)
    first = sorted_findings[0]
    pid, process_name = _finding_pid_process(first)
    evidence_groups = sorted({str(finding.get("category") or finding.get("rule_id") or "finding") for finding in sorted_findings})
    return {
        "finding_id": _text(first.get("id")),
        "pid_raw": pid,
        "pid": _text(pid),
        "process_name": _text(process_name),
        "identity": _process_identity(process_name, pid),
        "severity": _severity(first.get("severity")),
        "score": _text(sum(_int_value(finding.get("score")) for finding in sorted_findings)),
        "evidence_groups": evidence_groups,
        "component_rule_ids": sorted({_text(finding.get("rule_id") or finding.get("rule_name")) for finding in sorted_findings}),
        "memory_region_count": sum(1 for finding in sorted_findings if finding.get("artifact_type") == "memory_region_artifacts"),
        "network_endpoint_count": 0,
        "yara_rule_count": sum(1 for finding in sorted_findings if finding.get("artifact_type") == "yara_matches"),
        "yara_raw_match_count": 0,
        "recommendation": _text(first.get("recommendation"), "Review this process with the component evidence."),
        "explanation": "Grouped report-display summary built from related triage findings.",
    }


def build_process_finding_groups(findings: list[dict]) -> list[dict]:
    summaries = [finding for finding in findings if finding.get("category") == "process_risk_summary"]
    if summaries:
        groups = [_format_process_group_from_summary(finding) for finding in summaries]
        return sorted(groups, key=_process_group_sort_key, reverse=True)

    grouped: dict[tuple, list[dict]] = defaultdict(list)
    for finding in findings:
        key = _process_key(*_finding_pid_process(finding))
        if key is not None:
            grouped[key].append(finding)
    groups = [_format_process_group_from_findings(key, group_findings) for key, group_findings in grouped.items()]
    return sorted(groups, key=_process_group_sort_key, reverse=True)


def _index_by_pid(rows: list[dict], pid_getter=None) -> dict[str, list[dict]]:
    indexed: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        pid = pid_getter(row) if pid_getter else row.get("pid")
        key = _pid_key(pid)
        if key is not None:
            indexed[key].append(row)
    return indexed


def _yara_pid(match: dict):
    extra = _extra_data(match)
    if extra.get("pid") is not None:
        return extra.get("pid")
    return _pid_from_text(match.get("target_identifier"))


def _ioc_pid(ioc: dict):
    return _extra_data(ioc).get("pid")


def _format_region(row: dict) -> dict:
    return {
        "address_range": _text(_address_range(row)),
        "protection": _text(row.get("protection")),
        "source_plugin": _text(row.get("source_plugin")),
    }


def _network_endpoint(row: dict) -> str | None:
    remote_address = _raw_text(row.get("remote_address"))
    if not remote_address:
        return None
    remote_port = row.get("remote_port")
    return f"{remote_address}:{remote_port}" if remote_port is not None else remote_address


def _ioc_type_summary(rows: list[dict], limit: int = IOC_REPRESENTATIVE_LIMIT) -> list[dict]:
    grouped: dict[str, dict] = {}
    for row in rows:
        ioc_type = _text(row.get("ioc_type"), "unknown")
        bucket = grouped.setdefault(ioc_type, {"ioc_type": ioc_type, "count": 0, "values": []})
        bucket["count"] += 1
        value = _raw_text(row.get("value"))
        if value and value not in bucket["values"] and len(bucket["values"]) < limit:
            bucket["values"].append(value)
    return sorted(grouped.values(), key=lambda item: (-item["count"], item["ioc_type"]))


def _chain_interpretation(group: dict) -> str:
    groups = set(group.get("evidence_groups") or [])
    if "memory_region" in groups and ({"yara_match", "network_endpoint", "suspicious_command"} & groups):
        return "Multiple independent triage signals support further process-level investigation; this is not conclusive by itself."
    if "memory_region" in groups:
        return "Memory-region evidence supports injection triage and requires analyst validation."
    return "Grouped triage indicators should be reviewed with the underlying artifacts."


def build_memory_evidence_chains(process_groups: list[dict], artifacts: dict[str, list[dict]], iocs: list[dict], limit: int = TOP_PROCESS_LIMIT) -> list[dict]:
    memory_by_pid = _index_by_pid(artifacts.get("memory_region_artifacts", []))
    network_by_pid = _index_by_pid(artifacts.get("network_artifacts", []))
    yara_by_pid = _index_by_pid(artifacts.get("yara_matches", []), _yara_pid)
    ioc_by_pid = _index_by_pid(iocs, _ioc_pid)
    chains = []
    for group in process_groups[:limit]:
        pid_key = _pid_key(group.get("pid_raw"))
        memory_rows = memory_by_pid.get(pid_key, []) if pid_key else []
        network_rows = network_by_pid.get(pid_key, []) if pid_key else []
        yara_rows = yara_by_pid.get(pid_key, []) if pid_key else []
        ioc_rows = ioc_by_pid.get(pid_key, []) if pid_key else []
        yara_rules = sorted({_text(row.get("rule_name")) for row in yara_rows if _raw_text(row.get("rule_name"))})
        network_endpoints = []
        for row in network_rows:
            endpoint = _network_endpoint(row)
            if endpoint and endpoint not in network_endpoints:
                network_endpoints.append(endpoint)
            if len(network_endpoints) >= IOC_REPRESENTATIVE_LIMIT:
                break
        chains.append(
            {
                "identity": group["identity"],
                "pid": group["pid"],
                "process_name": group["process_name"],
                "severity": group["severity"],
                "score": group["score"],
                "evidence_groups": group["evidence_groups"],
                "memory_regions": [_format_region(row) for row in memory_rows[:3]],
                "memory_region_count": len(memory_rows),
                "yara_rules": yara_rules[:YARA_REPRESENTATIVE_LIMIT] or group.get("component_rule_ids", [])[:0],
                "yara_raw_match_count": group.get("yara_raw_match_count", 0),
                "network_endpoints": network_endpoints,
                "network_endpoint_count": group.get("network_endpoint_count", 0) or len(network_rows),
                "ioc_references": _ioc_type_summary(ioc_rows, limit=3),
                "interpretation": _chain_interpretation(group),
            }
        )
    return chains


def build_ioc_summary(iocs: list[dict]) -> list[dict]:
    grouped: dict[str, dict] = {}
    for ioc in iocs:
        ioc_type = _text(ioc.get("ioc_type"), "unknown")
        bucket = grouped.setdefault(
            ioc_type,
            {"ioc_type": ioc_type, "count": 0, "representative_values": [], "source_plugins": set(), "confidences": []},
        )
        bucket["count"] += 1
        value = _raw_text(ioc.get("value"))
        if value and value not in bucket["representative_values"] and len(bucket["representative_values"]) < IOC_REPRESENTATIVE_LIMIT:
            bucket["representative_values"].append(value)
        source_plugin = _raw_text(ioc.get("source_plugin"))
        if source_plugin:
            bucket["source_plugins"].add(source_plugin)
        confidence = ioc.get("confidence")
        if confidence is not None:
            bucket["confidences"].append(_int_value(confidence))

    rows = []
    for bucket in grouped.values():
        confidences = bucket["confidences"]
        confidence_range = "N/A"
        if confidences:
            confidence_range = f"{min(confidences)}-{max(confidences)}" if min(confidences) != max(confidences) else str(confidences[0])
        rows.append(
            {
                "ioc_type": bucket["ioc_type"],
                "count": bucket["count"],
                "representative_values": bucket["representative_values"],
                "source_plugins": sorted(bucket["source_plugins"]),
                "confidence_range": confidence_range,
            }
        )
    return sorted(rows, key=lambda row: (-row["count"], row["ioc_type"]))


def build_yara_summary(yara_matches: list[dict]) -> list[dict]:
    grouped: dict[tuple, dict] = {}
    for match in yara_matches:
        rule_name = _text(match.get("rule_name"), "Unknown rule")
        key = (rule_name, match.get("source_plugin"))
        bucket = grouped.setdefault(
            key,
            {"rule_name": rule_name, "match_count": 0, "targets": [], "sample_offsets": [], "source_plugins": set()},
        )
        bucket["match_count"] += 1
        target = _raw_text(match.get("target_identifier"))
        if target and target not in bucket["targets"] and len(bucket["targets"]) < YARA_REPRESENTATIVE_LIMIT:
            bucket["targets"].append(target)
        offset = _display_offset(match)
        if offset != "N/A" and offset not in bucket["sample_offsets"] and len(bucket["sample_offsets"]) < YARA_REPRESENTATIVE_LIMIT:
            bucket["sample_offsets"].append(offset)
        source_plugin = _raw_text(match.get("source_plugin"))
        if source_plugin:
            bucket["source_plugins"].add(source_plugin)
    rows = []
    for bucket in grouped.values():
        rows.append({**bucket, "source_plugins": sorted(bucket["source_plugins"])})
    return sorted(rows, key=lambda row: (-row["match_count"], row["rule_name"]))


def build_executive_summary(
    evidence: dict,
    analysis_job: dict,
    summary: dict,
    risk_findings: list[dict],
    iocs: list[dict],
    memory_regions: list[dict],
    yara_status: dict,
) -> dict:
    high_critical = sum(1 for finding in risk_findings if _is_high_priority(finding))
    executable_regions = sum(1 for region in memory_regions if region.get("is_executable"))
    return {
        "job_status": _text(analysis_job.get("status")),
        "evidence_filename": _text(evidence.get("original_filename")),
        "os_profile": f"{_text(evidence.get('os_family') or analysis_job.get('os_family'))} / {_text(analysis_job.get('plugin_profile'), 'Default')}",
        "plugin_status": f"{summary['completed_plugins']} of {summary['total_plugin_results']} completed; {summary['failed_plugins']} failed",
        "finding_count": len(risk_findings),
        "high_critical_count": high_critical,
        "ioc_count": len(iocs),
        "yara_status": yara_status.get("message") or "YARA status unavailable.",
        "memory_region_summary": f"{len(memory_regions)} memory region artifacts; {executable_regions} marked executable",
        "analyst_note": "These findings are triage indicators and require analyst validation. They are not conclusive by themselves.",
    }


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
    plugin_results_limited = limited(plugin_results, 100)
    yara_matches_limited = limited(artifacts.get("yara_matches", []))
    summary = build_summary(plugin_results, artifacts, risk_findings, iocs)
    yara_status = build_yara_status(row_dict(analysis_job), plugin_results_limited, yara_matches_limited)
    display_top, omitted_count = build_display_top_findings(risk_findings)
    process_groups = build_process_finding_groups(risk_findings)
    network_display = build_network_display(artifacts.get("network_artifacts", []), risk_findings, iocs)
    module_display = build_module_display(artifacts.get("module_artifacts", []), risk_findings)
    context = {
        "product_name": "RAMSight",
        "report_title": "RAMSight Technical Analysis Report",
        "report_type": "technical",
        "case": row_dict(case),
        "evidence": row_dict(evidence),
        "analysis_job": row_dict(analysis_job),
        "plugin_results": plugin_results_limited,
        "plugin_status_rows": build_plugin_status_rows(plugin_results_limited),
        "risk_findings": risk_findings,
        "top_findings": top_findings(risk_findings),
        "display_top_findings": display_top,
        "top_findings_omitted_count": omitted_count,
        "process_risk_summaries": limited([finding for finding in risk_findings if finding.get("category") == "process_risk_summary"]),
        "process_finding_groups": limited(process_groups),
        "process_artifacts": limited(artifacts.get("process_artifacts", [])),
        "network_display": network_display,
        "network_indicators": network_display["rows"],
        "module_display": module_display,
        "module_artifacts": module_display["rows"],
        "memory_regions": limited(artifacts.get("memory_region_artifacts", [])),
        "command_artifacts": limited(artifacts.get("command_artifacts", [])),
        "yara_matches": yara_matches_limited,
        "yara_summary": build_yara_summary(yara_matches_limited),
        "iocs": limited(iocs, 100),
        "ioc_summary": build_ioc_summary(iocs),
        "ioc_export_note": "Full IOC JSON and CSV exports are available separately when generated for this analysis job.",
        "analyst_notes": limited(analyst_notes or [], 20),
        "generated_at": generated_at or utc_now(),
        "summary": summary,
        "yara_status": yara_status,
    }
    context["executive_summary"] = build_executive_summary(
        context["evidence"],
        context["analysis_job"],
        summary,
        risk_findings,
        iocs,
        artifacts.get("memory_region_artifacts", []),
        yara_status,
    )
    context["memory_evidence_chains"] = build_memory_evidence_chains(process_groups, artifacts, iocs)
    context["recommendations"] = generate_recommendations(context)
    return context
