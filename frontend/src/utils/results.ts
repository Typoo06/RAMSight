import type { IOC, RiskFinding } from "../types/domain";

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

const OMITTED_CONTEXT_VALUES = new Set([
  "",
  "address unavailable",
  "disabled",
  "n/a",
  "none",
  "not recorded",
  "null",
  "unknown",
  "unknown-unknown",
]);

type ExtraData = Record<string, unknown>;

function includesText(value: string | null | undefined, pattern: string): boolean {
  return (value ?? "").toLowerCase().includes(pattern);
}

function asRecord(value: unknown): ExtraData {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return value as ExtraData;
}

function contextText(value: unknown): string | null {
  if (value === null || value === undefined || typeof value === "object") return null;
  const text = String(value).trim();
  if (OMITTED_CONTEXT_VALUES.has(text.toLowerCase())) return null;
  return text;
}

function firstContextText(records: ExtraData[], keys: string[]): string | null {
  for (const record of records) {
    for (const key of keys) {
      const value = contextText(record[key]);
      if (value) return value;
    }
  }
  return null;
}

function addressRangeFromContext(records: ExtraData[]): string | null {
  const addressRange = firstContextText(records, ["address_range", "region", "memory_region"]);
  if (addressRange) return addressRange;

  const startAddress = firstContextText(records, ["start_address", "start", "vad_start"]);
  const endAddress = firstContextText(records, ["end_address", "end", "vad_end"]);
  if (!startAddress || !endAddress) return null;
  return `${startAddress}-${endAddress}`;
}

function endpointFromContext(records: ExtraData[]): string | null {
  const explicitEndpoint = firstContextText(records, ["network_endpoint", "remote_endpoint", "endpoint"]);
  if (explicitEndpoint) return explicitEndpoint;

  const remoteAddress = firstContextText(records, ["remote_address", "ip_address"]);
  if (!remoteAddress) return null;

  const remotePort = firstContextText(records, ["remote_port", "port"]);
  return remotePort ? `${remoteAddress}:${remotePort}` : remoteAddress;
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

export function findingEvidenceContext(finding: RiskFinding): string[] {
  const extraData = asRecord(finding.extra_data);
  const linkedArtifacts = asRecord(extraData.linked_artifacts);
  const records = [extraData, linkedArtifacts];
  const parts: string[] = [];

  const pid = firstContextText(records, ["pid"]);
  const processName = firstContextText(records, ["process_name", "name"]);
  if (processName && pid) {
    parts.push(`${processName} (PID ${pid})`);
  } else if (processName) {
    parts.push(processName);
  } else if (pid) {
    parts.push(`PID ${pid}`);
  }

  const addressRange = addressRangeFromContext(records);
  if (addressRange) parts.push(`region ${addressRange}`);

  const endpoint = endpointFromContext(records);
  if (endpoint) parts.push(`endpoint ${endpoint}`);

  const yaraRule = firstContextText(records, ["rule_name", "yara_rule", "yara_rule_name"]);
  if (yaraRule && isYaraFinding(finding)) parts.push(`YARA ${yaraRule}`);

  if (isProcessRiskSummary(finding)) {
    const summaryParts = [
      ["components", firstContextText([extraData], ["unique_component_count"])],
      ["regions", firstContextText([extraData], ["memory_region_count"])],
      ["endpoints", firstContextText([extraData], ["network_endpoint_count"])],
      ["YARA", firstContextText([extraData], ["yara_match_count"])],
    ]
      .filter(([, value]) => value)
      .map(([label, value]) => `${label} ${value}`);
    if (summaryParts.length > 0) parts.push(summaryParts.join(", "));
  }

  return parts;
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
