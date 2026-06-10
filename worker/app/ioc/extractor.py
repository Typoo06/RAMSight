# IOC extraction from normalized artifacts and risk findings.

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from uuid import UUID

from app.detection.engine import command_has_encoded_powershell
from app.detection.path_reputation import known_microsoft_appdata_path
from app.ioc.dedup import deduplicate_iocs, normalize_ioc_value, normalize_path
from app.ioc.types import (
    IOC_COMMAND_LINE,
    IOC_FILE_PATH,
    IOC_IP_ADDRESS,
    IOC_MEMORY_REGION,
    IOC_MODULE_PATH,
    IOC_NETWORK_ENDPOINT,
    IOC_PID,
    IOC_PLUGIN_REFERENCE,
    IOC_PROCESS_NAME,
    IOC_YARA_RULE,
    IOCRecordDraft,
)
from app.parsers.common import is_path_like, is_placeholder_value

PROCESS_TABLE = "process_artifacts"
NETWORK_TABLE = "network_artifacts"
MODULE_TABLE = "module_artifacts"
MEMORY_REGION_TABLE = "memory_region_artifacts"
COMMAND_TABLE = "command_artifacts"
YARA_TABLE = "yara_matches"

SUSPICIOUS_COMMAND_KEYWORDS = {
    "invoke-expression",
    "downloadstring",
    "frombase64string",
    "mimikatz",
    "rundll32",
    "certutil",
    "powershell -enc",
    "powershell.exe -enc",
    "curl ",
    "wget ",
}
USER_WRITABLE_PATH_FRAGMENTS = {
    "/temp/",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/appdata/",
    "/users/public/",
    "/downloads/",
    "/home/",
}
WHITESPACE_RE = re.compile(r"\s+")


def extract_iocs(artifacts: dict[str, list[dict]], risk_findings: list[dict], context: dict) -> list[IOCRecordDraft]:
    risk_index = index_risk_findings(risk_findings)
    iocs: list[IOCRecordDraft] = []
    iocs.extend(extract_network_iocs(artifacts.get(NETWORK_TABLE, []), risk_index, context))
    iocs.extend(extract_command_iocs(artifacts.get(COMMAND_TABLE, []), risk_index, context))
    iocs.extend(extract_module_iocs(artifacts.get(MODULE_TABLE, []), risk_index, context))
    iocs.extend(extract_process_iocs(artifacts.get(PROCESS_TABLE, []), risk_index, context))
    iocs.extend(extract_yara_iocs(artifacts.get(YARA_TABLE, []), risk_index, context))
    iocs.extend(extract_memory_region_iocs(artifacts.get(MEMORY_REGION_TABLE, []), risk_index, context))
    iocs.extend(extract_plugin_reference_iocs(risk_findings, context))
    return deduplicate_iocs(iocs)


def index_risk_findings(risk_findings: list[dict]) -> dict[tuple[str, str], list[dict]]:
    indexed: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for finding in risk_findings:
        if finding.get("category") == "process_risk_summary":
            continue
        artifact_type = finding.get("artifact_type")
        artifact_id = finding.get("artifact_id")
        if artifact_type and artifact_id:
            indexed[(str(artifact_type), str(artifact_id))].append(finding)
    return indexed


def linked_findings(risk_index: dict[tuple[str, str], list[dict]], table_name: str, artifact: dict) -> list[dict]:
    artifact_id = artifact.get("id")
    if artifact_id is None:
        return []
    return risk_index.get((table_name, str(artifact_id)), [])


def is_public_ip(value: str | None) -> bool:
    address = parse_ip(value)
    if address is None:
        return False
    return not (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    )


def parse_ip(value: str | None):
    if not value:
        return None
    try:
        return ipaddress.ip_address(str(value).strip().strip("[]"))
    except ValueError:
        return None


def confidence_for_severity(severity: str | None, default: int = 60) -> int:
    return {"critical": 95, "high": 85, "medium": 65, "low": 45}.get((severity or "").lower(), default)


def severity_from_findings(findings: list[dict], default: str = "medium") -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    severities = [str(finding.get("severity") or default).lower() for finding in findings]
    return max(severities or [default], key=lambda severity: order.get(severity, 0))


def make_ioc(
    context: dict,
    ioc_type: str,
    value: object,
    source_plugin: str | None,
    confidence: int,
    text_context: str,
    extra_data: dict,
    risk_finding_id: UUID | None = None,
) -> IOCRecordDraft | None:
    if is_placeholder_value(value):
        return None
    value_text = str(value)
    os_family = (context.get("os_family") or "unknown").lower()
    return IOCRecordDraft(
        analysis_job_id=context["analysis_job_id"],
        evidence_id=context["evidence_id"],
        risk_finding_id=risk_finding_id,
        os_family=os_family,
        source_plugin=source_plugin,
        ioc_type=ioc_type,
        value=value_text,
        normalized_value=normalize_ioc_value(ioc_type, value_text, os_family),
        context=text_context,
        confidence=confidence,
        extra_data=extra_data,
    )


def append_if_present(iocs: list[IOCRecordDraft], ioc: IOCRecordDraft | None) -> None:
    if ioc is not None:
        iocs.append(ioc)


def first_finding_id(findings: list[dict]) -> UUID | None:
    return findings[0].get("id") if findings else None


def extract_network_iocs(rows: list[dict], risk_index: dict[tuple[str, str], list[dict]], context: dict) -> list[IOCRecordDraft]:
    iocs = []
    for row in rows:
        findings = linked_findings(risk_index, NETWORK_TABLE, row)
        remote_address = row.get("remote_address")
        remote_port = row.get("remote_port")
        public = is_public_ip(remote_address)
        if not public and not findings:
            continue
        severity = severity_from_findings(findings, "medium" if public else "low")
        confidence = confidence_for_severity(severity, 70 if public else 35)
        if not public:
            confidence = min(confidence, 40)
        extra_data = network_extra(row, severity, "public remote address" if public else "linked non-public remote address")
        append_if_present(
            iocs,
            make_ioc(
                context,
                IOC_IP_ADDRESS,
                remote_address,
                row.get("source_plugin"),
                confidence,
                extra_data["matched_reason"],
                extra_data,
                first_finding_id(findings),
            ),
        )
        if remote_port is not None:
            append_if_present(
                iocs,
                make_ioc(
                    context,
                    IOC_NETWORK_ENDPOINT,
                    f"{remote_address}:{remote_port}",
                    row.get("source_plugin"),
                    confidence,
                    extra_data["matched_reason"],
                    extra_data,
                    first_finding_id(findings),
                ),
            )
    return iocs


def network_extra(row: dict, severity: str, matched_reason: str) -> dict:
    return {
        "ioc_role": "threat_ioc",
        "severity": severity,
        "matched_reason": matched_reason,
        "protocol": row.get("protocol"),
        "local_address": row.get("local_address"),
        "local_port": row.get("local_port"),
        "remote_address": row.get("remote_address"),
        "remote_port": row.get("remote_port"),
        "pid": row.get("pid"),
        "process_name": row.get("process_name"),
        "source_plugin": row.get("source_plugin"),
    }


def is_suspicious_command(command: str | None) -> tuple[bool, str | None]:
    if not command:
        return False, None
    if command_has_encoded_powershell(command):
        return True, "encoded PowerShell command"
    lowered = WHITESPACE_RE.sub(" ", command.lower())
    for keyword in sorted(SUSPICIOUS_COMMAND_KEYWORDS):
        if keyword in lowered:
            return True, f"suspicious command keyword: {keyword.strip()}"
    return False, None


def extract_command_iocs(rows: list[dict], risk_index: dict[tuple[str, str], list[dict]], context: dict) -> list[IOCRecordDraft]:
    iocs = []
    for row in rows:
        findings = linked_findings(risk_index, COMMAND_TABLE, row)
        suspicious, reason = is_suspicious_command(row.get("command"))
        if not suspicious and not findings:
            continue
        severity = severity_from_findings(findings, "high" if suspicious else "medium")
        append_if_present(
            iocs,
            make_ioc(
                context,
                IOC_COMMAND_LINE,
                row.get("command"),
                row.get("source_plugin"),
                confidence_for_severity(severity, 80),
                reason or "linked risk finding",
                {
                    "ioc_role": "threat_ioc",
                    "severity": severity,
                    "matched_reason": reason or "linked risk finding",
                    "pid": row.get("pid"),
                    "process_name": row.get("process_name"),
                    "shell_type": row.get("shell_type"),
                    "source_plugin": row.get("source_plugin"),
                },
                first_finding_id(findings),
            ),
        )
    return iocs


def is_suspicious_path(path: str | None, os_family: str | None) -> tuple[bool, str | None]:
    if not is_path_like(path, os_family):
        return False, None
    normalized = normalize_path(path, os_family)
    for fragment in sorted(USER_WRITABLE_PATH_FRAGMENTS):
        if fragment in normalized:
            return True, f"user-writable path fragment: {fragment}"
    return False, None


def extract_module_iocs(rows: list[dict], risk_index: dict[tuple[str, str], list[dict]], context: dict) -> list[IOCRecordDraft]:
    iocs = []
    os_family = context.get("os_family")
    for row in rows:
        module_path = row.get("module_path")
        if not is_path_like(module_path, os_family):
            continue
        reputation = known_microsoft_appdata_path(module_path, os_family)
        findings = linked_findings(risk_index, MODULE_TABLE, row)
        if reputation and not findings:
            continue
        suspicious, reason = is_suspicious_path(module_path, os_family)
        if not suspicious and not findings:
            continue
        severity = severity_from_findings(findings, "medium")
        matched_reason = reason or "linked risk finding"
        extra_data = {
            "ioc_role": "threat_ioc" if not reputation else "investigation_artifact",
            "severity": severity,
            "matched_reason": matched_reason,
            "module_name": row.get("module_name"),
            "pid": row.get("pid"),
            "process_name": row.get("process_name"),
            "source_plugin": row.get("source_plugin"),
        }
        if reputation:
            matched_reason = "linked finding with known Microsoft AppData module context"
            extra_data.update(
                {
                    "matched_reason": matched_reason,
                    "known_microsoft_appdata_module": True,
                    "module_app_name": reputation.app_name,
                    "module_app_root": reputation.normalized_root,
                }
            )
        append_if_present(
            iocs,
            make_ioc(
                context,
                IOC_MODULE_PATH,
                module_path,
                row.get("source_plugin"),
                confidence_for_severity(severity, 70),
                matched_reason,
                extra_data,
                first_finding_id(findings),
            ),
        )
    return iocs


def extract_process_iocs(rows: list[dict], risk_index: dict[tuple[str, str], list[dict]], context: dict) -> list[IOCRecordDraft]:
    iocs = []
    for row in rows:
        findings = linked_findings(risk_index, PROCESS_TABLE, row)
        suspicious_path, reason = is_suspicious_path(row.get("image_path"), context.get("os_family"))
        hidden_candidate = bool(row.get("is_hidden_candidate")) and bool(findings)
        if not findings and not suspicious_path and not hidden_candidate:
            continue
        severity = severity_from_findings(findings, "high" if hidden_candidate else "medium")
        matched_reason = reason or "linked risk finding"
        append_if_present(
            iocs,
            make_ioc(
                context,
                IOC_PROCESS_NAME,
                row.get("name"),
                row.get("source_plugin"),
                confidence_for_severity(severity, 70),
                matched_reason,
                process_extra(row, severity, matched_reason),
                first_finding_id(findings),
            ),
        )
        if findings or hidden_candidate:
            append_if_present(
                iocs,
                make_ioc(
                    context,
                    IOC_PID,
                    row.get("pid"),
                    row.get("source_plugin"),
                    min(confidence_for_severity(severity, 60), 70),
                    "contextual PID linked to concrete suspicious process evidence",
                    process_extra(row, severity, matched_reason),
                    first_finding_id(findings),
                ),
            )
        if is_path_like(row.get("image_path"), context.get("os_family")) and (suspicious_path or findings):
            append_if_present(
                iocs,
                make_ioc(
                    context,
                    IOC_FILE_PATH,
                    row.get("image_path"),
                    row.get("source_plugin"),
                    confidence_for_severity(severity, 70),
                    matched_reason,
                    process_extra(row, severity, matched_reason),
                    first_finding_id(findings),
                ),
            )
    return iocs


def memory_region_value(row: dict, index: int) -> str:
    pid = row.get("pid")
    start = row.get("start_address")
    end = row.get("end_address")
    if start and end:
        return f"{pid}:{start}-{end}"
    if pid is not None:
        return f"pid:{pid}:malfind-region:{index}"
    return f"malfind-region:{index}"


def process_extra(row: dict, severity: str, matched_reason: str) -> dict:
    return {
        "ioc_role": "investigation_artifact",
        "severity": severity,
        "matched_reason": matched_reason,
        "pid": row.get("pid"),
        "ppid": row.get("ppid"),
        "process_name": row.get("name") or row.get("process_name"),
        "image_path": row.get("image_path"),
        "source_plugin": row.get("source_plugin"),
    }


def metadata_text(metadata: dict, row: dict | None = None) -> str:
    values = [row.get("rule_name") if row else None]
    values.extend(metadata.values())
    parts: list[str] = []
    for value in values:
        if isinstance(value, (list, tuple, set)):
            parts.extend(str(item) for item in value)
        elif isinstance(value, dict):
            parts.extend(str(item) for item in value.values())
        elif value is not None:
            parts.append(str(value))
    return " ".join(parts).lower()


def yara_is_malware_specific(row: dict) -> bool:
    metadata = row.get("extra_data") or {}
    family = str(metadata.get("malware_family") or metadata.get("family") or "").lower()
    category = str(metadata.get("rule_category") or metadata.get("category") or "").lower()
    description = str(metadata.get("description") or "").lower()
    rule_name = str(row.get("rule_name") or "").lower()
    text = " ".join([family, category, description, rule_name])
    if family and family not in {"generic", "unknown", "n/a", "none"}:
        return True
    if any(term in text for term in ["cobalt", "beacon", "malware", "trojan", "loader", "backdoor", "ransom", "mimikatz"]):
        return True
    return False


def yara_is_cross_platform_mismatch(row: dict, context: dict) -> bool:
    if str(context.get("os_family") or "").lower() != "windows":
        return False
    metadata = row.get("extra_data") or {}
    text = metadata_text(metadata, row)
    mismatch_terms = [
        "linux",
        "elf",
        "mach-o",
        "macho",
        "macos",
        "osx",
        "darwin",
        "android",
    ]
    windows_terms = ["windows", "win_", "win32", "win64", "pe32", "powershell", "cobaltstrike"]
    return any(term in text for term in mismatch_terms) and not any(term in text for term in windows_terms)


def yara_has_correlation(findings: list[dict]) -> bool:
    for finding in findings:
        extra = finding.get("extra_data") or {}
        if extra.get("linked_memory_region_artifact_ids"):
            return True
        groups = extra.get("evidence_groups") or []
        if isinstance(groups, list) and any(group in groups for group in ["memory_region", "network_endpoint", "suspicious_command", "suspicious_module"]):
            return True
        confidence = str(extra.get("detection_confidence") or "").lower()
        if confidence == "probable_malware":
            return True
    return False


def yara_ioc_role(row: dict, findings: list[dict], context: dict) -> str:
    if yara_is_cross_platform_mismatch(row, context):
        return "investigation_artifact"
    if yara_is_malware_specific(row) and yara_has_correlation(findings):
        return "threat_ioc"
    return "investigation_artifact"


def extract_yara_iocs(rows: list[dict], risk_index: dict[tuple[str, str], list[dict]], context: dict) -> list[IOCRecordDraft]:
    iocs = []
    for row in rows:
        metadata = row.get("extra_data") or {}
        severity = str(metadata.get("severity") or "high").lower()
        findings = linked_findings(risk_index, YARA_TABLE, row)
        role = yara_ioc_role(row, findings, context)
        confidence = confidence_for_severity(severity, 85)
        if role != "threat_ioc":
            confidence = min(confidence, 55)
        append_if_present(
            iocs,
            make_ioc(
                context,
                IOC_YARA_RULE,
                row.get("rule_name"),
                row.get("source_plugin"),
                confidence,
                "YARA rule matched memory content; role reflects rule specificity and correlation strength",
                {
                    "ioc_role": role,
                    "severity": severity,
                    "malware_specific": yara_is_malware_specific(row),
                    "correlated": yara_has_correlation(findings),
                    "cross_platform_mismatch": yara_is_cross_platform_mismatch(row, context),
                    "namespace": row.get("namespace"),
                    "tags": row.get("tags"),
                    "target_identifier": row.get("target_identifier"),
                    "target_type": row.get("target_type"),
                    "offset": row.get("offset"),
                    "matched_text_excerpt": row.get("matched_text_excerpt"),
                    "source_plugin": row.get("source_plugin"),
                },
            ),
        )
    return iocs


def extract_memory_region_iocs(rows: list[dict], risk_index: dict[tuple[str, str], list[dict]], context: dict) -> list[IOCRecordDraft]:
    iocs = []
    for index, row in enumerate(rows, start=1):
        findings = linked_findings(risk_index, MEMORY_REGION_TABLE, row)
        suspicious = bool(row.get("is_executable")) or row.get("source_plugin") in {"windows.malfind", "linux.vmayarascan"}
        if not suspicious and not findings:
            continue
        value = memory_region_value(row, index)
        severity = severity_from_findings(findings, "high" if suspicious else "medium")
        append_if_present(
            iocs,
            make_ioc(
                context,
                IOC_MEMORY_REGION,
                value,
                row.get("source_plugin"),
                confidence_for_severity(severity, 80),
                "suspicious memory region",
                {
                    "ioc_role": "investigation_artifact",
                    "severity": severity,
                    "matched_reason": "suspicious memory region",
                    "pid": row.get("pid"),
                    "process_name": row.get("process_name"),
                    "start_address": row.get("start_address"),
                    "end_address": row.get("end_address"),
                    "protection": row.get("protection"),
                    "description": row.get("description"),
                    "is_executable": row.get("is_executable"),
                    "is_private": row.get("is_private"),
                    "region_index": index,
                    "source_plugin": row.get("source_plugin"),
                },
                first_finding_id(findings),
            ),
        )
    return iocs


def extract_plugin_reference_iocs(risk_findings: list[dict], context: dict) -> list[IOCRecordDraft]:
    iocs = []
    for finding in risk_findings:
        if finding.get("category") == "process_risk_summary" or not finding.get("source_plugin"):
            continue
        severity = str(finding.get("severity") or "low").lower()
        append_if_present(
            iocs,
            make_ioc(
                context,
                IOC_PLUGIN_REFERENCE,
                finding.get("source_plugin"),
                finding.get("source_plugin"),
                min(confidence_for_severity(severity, 45), 60),
                "plugin source reference from concrete risk finding",
                {
                    "ioc_role": "investigation_artifact",
                    "severity": severity,
                    "rule_id": finding.get("rule_id"),
                    "rule_name": finding.get("rule_name"),
                    "risk_finding_id": str(finding.get("id")),
                },
                finding.get("id"),
            ),
        )
    return iocs
