import type { IOC, RiskFinding } from "../types/domain";

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

function includesText(value: string | null | undefined, pattern: string): boolean {
  return (value ?? "").toLowerCase().includes(pattern);
}

export function severityRank(severity: string): number {
  return SEVERITY_RANK[severity.toLowerCase()] ?? 0;
}

export function sortFindingsByRisk(findings: RiskFinding[]): RiskFinding[] {
  return [...findings].sort((left, right) => {
    const severityDifference = severityRank(right.severity) - severityRank(left.severity);
    if (severityDifference !== 0) return severityDifference;
    return right.score - left.score;
  });
}

export function isProcessRiskSummary(finding: RiskFinding): boolean {
  return finding.category === "process_risk_summary" || finding.rule_id === "PROCESS_RISK_SUMMARY";
}

export function isNetworkFinding(finding: RiskFinding): boolean {
  return (
    finding.artifact_type === "network_artifacts" ||
    includesText(finding.category, "network") ||
    includesText(finding.source_plugin, "netscan")
  );
}

export function isModuleOrPathFinding(finding: RiskFinding): boolean {
  return (
    finding.artifact_type === "module_artifacts" ||
    includesText(finding.category, "module") ||
    includesText(finding.category, "path") ||
    includesText(finding.title, "path")
  );
}

export function isMemoryRegionFinding(finding: RiskFinding): boolean {
  return (
    finding.artifact_type === "memory_region_artifacts" ||
    includesText(finding.category, "memory") ||
    includesText(finding.source_plugin, "malfind") ||
    includesText(finding.source_plugin, "vmayarascan")
  );
}

export function isYaraFinding(finding: RiskFinding): boolean {
  return includesText(finding.category, "yara") || includesText(finding.source_plugin, "yara") || includesText(finding.rule_name, "yara");
}

export function isNetworkIOC(ioc: IOC): boolean {
  return ["ip_address", "network_endpoint"].includes(ioc.ioc_type);
}

export function isModuleOrPathIOC(ioc: IOC): boolean {
  return ["module_path", "file_path"].includes(ioc.ioc_type);
}

export function isMemoryRegionIOC(ioc: IOC): boolean {
  return ioc.ioc_type === "memory_region";
}

export function isYaraIOC(ioc: IOC): boolean {
  return ioc.ioc_type === "yara_rule";
}

