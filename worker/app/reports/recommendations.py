# Cautious incident response recommendation helpers.


def generate_recommendations(report_context: dict) -> list[str]:
    findings = report_context.get("risk_findings") or []
    iocs = report_context.get("iocs") or []
    memory_regions = report_context.get("memory_regions") or []
    yara_matches = report_context.get("yara_matches") or []
    commands = report_context.get("command_artifacts") or []

    recommendations = [
        "Preserve the original memory image and associated hashes before any further handling.",
        "Validate suspicious findings against host timeline, process lineage, and endpoint telemetry before making a malware determination.",
    ]
    if any((finding.get("severity") or "").lower() in {"critical", "high"} for finding in findings):
        recommendations.append(
            "High or critical findings are present; consider isolating the host while preserving volatile and disk evidence."
        )
    if any(ioc.get("ioc_type") in {"ip_address", "network_endpoint"} for ioc in iocs):
        recommendations.append(
            "Hunt extracted network indicators in firewall, proxy, DNS, EDR, and SIEM logs for related activity."
        )
    if memory_regions:
        recommendations.append(
            "Review suspicious memory region candidates with process context, permissions, and raw plugin references."
        )
    if yara_matches:
        recommendations.append(
            "Validate YARA match quality and scope, then check related hosts and historical telemetry for the same rule hits."
        )
    if commands:
        recommendations.append(
            "Review suspicious command lines for persistence, download activity, and parent-child process relationships."
        )
    return recommendations
