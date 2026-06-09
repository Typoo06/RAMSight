import { Badge } from "../ui/Badge";
import type {
  IOC,
  MemoryRegionArtifact,
  NetworkArtifact,
  ProcessArtifact,
  RiskFinding,
  YaraMatchArtifact,
} from "../../types/domain";
import { severityRank } from "../../utils/results";
import { statusTone } from "../../utils/status";

interface MemoryEvidenceGraphProps {
  findings: RiskFinding[];
  focusPid: number | null;
  iocs: IOC[];
  memoryRegions: MemoryRegionArtifact[];
  networkArtifacts: NetworkArtifact[];
  processArtifacts: ProcessArtifact[];
  yaraMatches: YaraMatchArtifact[];
  limit?: number;
}

interface RelationshipGroup {
  findingIds: Set<string>;
  iocSamples: Set<string>;
  iocTypeCounts: Map<string, number>;
  key: string;
  memoryRegionCountHint: number;
  memoryRegionSamples: Set<string>;
  networkEndpointCountHint: number;
  networkEndpoints: Set<string>;
  pid: number;
  processName: string | null;
  score: number;
  severity: string | null;
  yaraRuleCountHint: number;
  yaraRules: Set<string>;
}

type ExtraData = Record<string, unknown>;

const OMITTED_VALUES = new Set([
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

function asRecord(value: unknown): ExtraData {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return value as ExtraData;
}

function textValue(value: unknown): string | null {
  if (value === null || value === undefined || typeof value === "object") return null;
  const text = String(value).trim();
  if (OMITTED_VALUES.has(text.toLowerCase())) return null;
  return text;
}

function numericValue(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return Math.trunc(value);
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!/^\d+$/.test(trimmed)) return null;
  return Number(trimmed);
}

function firstText(records: ExtraData[], keys: string[]): string | null {
  for (const record of records) {
    for (const key of keys) {
      const value = textValue(record[key]);
      if (value) return value;
    }
  }
  return null;
}

function firstNumber(records: ExtraData[], keys: string[]): number | null {
  for (const record of records) {
    for (const key of keys) {
      const value = numericValue(record[key]);
      if (value !== null) return value;
    }
  }
  return null;
}

function pidFromTargetIdentifier(value: string | null | undefined): number | null {
  const target = textValue(value);
  if (!target) return null;
  const exact = target.match(/^\d+$/);
  if (exact) return Number(exact[0]);
  const pidLabel = target.match(/^pid\s+(\d+)$/i);
  return pidLabel ? Number(pidLabel[1]) : null;
}

function addressRangeFromRecords(records: ExtraData[]): string | null {
  const explicitRange = firstText(records, ["address_range", "region", "memory_region"]);
  if (explicitRange) return explicitRange;

  const startAddress = firstText(records, ["start_address", "start", "vad_start"]);
  const endAddress = firstText(records, ["end_address", "end", "vad_end"]);
  if (!startAddress || !endAddress) return null;
  return `${startAddress}-${endAddress}`;
}

function addressRange(region: MemoryRegionArtifact): string | null {
  if (!region.start_address || !region.end_address) return null;
  return `${region.start_address}-${region.end_address}`;
}

function endpointFromRecords(records: ExtraData[]): string | null {
  const explicitEndpoint = firstText(records, ["network_endpoint", "remote_endpoint", "endpoint"]);
  if (explicitEndpoint) return explicitEndpoint;

  const remoteAddress = firstText(records, ["remote_address", "ip_address"]);
  if (!remoteAddress) return null;
  const remotePort = firstText(records, ["remote_port", "port"]);
  return remotePort ? `${remoteAddress}:${remotePort}` : remoteAddress;
}

function networkEndpoint(network: NetworkArtifact): string | null {
  const remoteAddress = textValue(network.remote_address);
  if (!remoteAddress) return null;
  const remotePort = network.remote_port === null ? null : String(network.remote_port);
  return remotePort ? `${remoteAddress}:${remotePort}` : remoteAddress;
}

function groupKey(pid: number): string {
  return `pid:${pid}`;
}

function createGroup(pid: number): RelationshipGroup {
  return {
    findingIds: new Set(),
    iocSamples: new Set(),
    iocTypeCounts: new Map(),
    key: groupKey(pid),
    memoryRegionCountHint: 0,
    memoryRegionSamples: new Set(),
    networkEndpointCountHint: 0,
    networkEndpoints: new Set(),
    pid,
    processName: null,
    score: 0,
    severity: null,
    yaraRuleCountHint: 0,
    yaraRules: new Set(),
  };
}

function getGroup(groups: Map<string, RelationshipGroup>, pid: number): RelationshipGroup {
  const key = groupKey(pid);
  const existing = groups.get(key);
  if (existing) return existing;
  const group = createGroup(pid);
  groups.set(key, group);
  return group;
}

function setProcessName(group: RelationshipGroup, value: unknown): void {
  if (group.processName) return;
  const processName = textValue(value);
  if (processName) group.processName = processName;
}

function setSeverity(group: RelationshipGroup, severity: string | null | undefined): void {
  const value = textValue(severity);
  if (!value) return;
  if (!group.severity || severityRank(value) > severityRank(group.severity)) {
    group.severity = value;
  }
}

function addIoc(group: RelationshipGroup, ioc: IOC): void {
  const type = textValue(ioc.ioc_type) ?? "ioc";
  group.iocTypeCounts.set(type, (group.iocTypeCounts.get(type) ?? 0) + 1);
  const value = textValue(ioc.value);
  if (value && group.iocSamples.size < 4) group.iocSamples.add(`${type}: ${value}`);
}

function addArrayText(values: unknown, target: Set<string>, limit: number): void {
  if (!Array.isArray(values)) return;
  for (const item of values) {
    const value = textValue(item);
    if (value && target.size < limit) target.add(value);
  }
}

function countFromGroup(group: RelationshipGroup): {
  findingCount: number;
  iocCount: number;
  memoryRegionCount: number;
  networkEndpointCount: number;
  yaraRuleCount: number;
} {
  const iocCount = [...group.iocTypeCounts.values()].reduce((total, value) => total + value, 0);
  return {
    findingCount: group.findingIds.size,
    iocCount,
    memoryRegionCount: Math.max(group.memoryRegionSamples.size, group.memoryRegionCountHint),
    networkEndpointCount: Math.max(group.networkEndpoints.size, group.networkEndpointCountHint),
    yaraRuleCount: Math.max(group.yaraRules.size, group.yaraRuleCountHint),
  };
}

function evidenceRichness(group: RelationshipGroup): number {
  const counts = countFromGroup(group);
  return counts.memoryRegionCount * 4
    + counts.yaraRuleCount * 4
    + counts.networkEndpointCount * 3
    + counts.iocCount * 2
    + counts.findingCount;
}

function buildRelationshipGroups({
  findings,
  focusPid,
  iocs,
  memoryRegions,
  networkArtifacts,
  processArtifacts,
  yaraMatches,
  limit,
}: MemoryEvidenceGraphProps): RelationshipGroup[] {
  const groups = new Map<string, RelationshipGroup>();
  const findingPidById = new Map<string, number>();

  for (const process of processArtifacts) {
    if (process.pid === null) continue;
    const group = getGroup(groups, process.pid);
    setProcessName(group, process.name);
  }

  for (const region of memoryRegions) {
    if (region.pid === null) continue;
    const group = getGroup(groups, region.pid);
    setProcessName(group, region.process_name);
    const range = addressRange(region);
    if (range) group.memoryRegionSamples.add(range);
  }

  for (const network of networkArtifacts) {
    if (network.pid === null) continue;
    const group = getGroup(groups, network.pid);
    setProcessName(group, network.process_name);
    const endpoint = networkEndpoint(network);
    if (endpoint) group.networkEndpoints.add(endpoint);
  }

  for (const match of yaraMatches) {
    const extraData = asRecord(match.extra_data);
    const pid = firstNumber([extraData], ["pid", "process_id"]) ?? pidFromTargetIdentifier(match.target_identifier);
    if (pid === null) continue;
    const group = getGroup(groups, pid);
    setProcessName(group, extraData.process_name);
    group.yaraRules.add(match.rule_name);
    group.yaraRuleCountHint = Math.max(group.yaraRuleCountHint, group.yaraRules.size);
  }

  for (const finding of findings) {
    const extraData = asRecord(finding.extra_data);
    const linkedArtifacts = asRecord(extraData.linked_artifacts);
    const records = [extraData, linkedArtifacts];
    const pid = firstNumber(records, ["pid", "process_id"]);
    if (pid === null) continue;
    findingPidById.set(finding.id, pid);
    const group = getGroup(groups, pid);
    group.findingIds.add(finding.id);
    setProcessName(group, firstText(records, ["process_name", "name"]));
    setSeverity(group, finding.effective_severity ?? finding.severity);
    group.score = Math.max(group.score, finding.score);

    const address = addressRangeFromRecords(records);
    if (address) group.memoryRegionSamples.add(address);
    const endpoint = endpointFromRecords(records);
    if (endpoint) group.networkEndpoints.add(endpoint);
    const yaraRule = firstText(records, ["rule_name", "yara_rule", "yara_rule_name"]);
    if (yaraRule) group.yaraRules.add(yaraRule);

    group.memoryRegionCountHint = Math.max(group.memoryRegionCountHint, firstNumber([extraData], ["memory_region_count"]) ?? 0);
    group.networkEndpointCountHint = Math.max(group.networkEndpointCountHint, firstNumber([extraData], ["network_endpoint_count"]) ?? 0);
    group.yaraRuleCountHint = Math.max(group.yaraRuleCountHint, firstNumber([extraData], ["yara_rule_count"]) ?? 0);
    addArrayText(extraData.yara_rules, group.yaraRules, 8);
  }

  for (const ioc of iocs) {
    const extraData = asRecord(ioc.extra_data);
    const linkedArtifacts = asRecord(extraData.linked_artifacts);
    const pid = firstNumber([extraData, linkedArtifacts], ["pid", "process_id"]) ?? (ioc.risk_finding_id ? findingPidById.get(ioc.risk_finding_id) ?? null : null);
    if (pid === null) continue;
    const group = getGroup(groups, pid);
    setProcessName(group, firstText([extraData, linkedArtifacts], ["process_name", "name"]));
    addIoc(group, ioc);
    if (ioc.ioc_type === "yara_rule") group.yaraRules.add(ioc.value);
  }

  const filteredGroups = [...groups.values()]
    .filter((group) => {
      if (focusPid !== null && group.pid !== focusPid) return false;
      const counts = countFromGroup(group);
      return counts.findingCount > 0
        || counts.iocCount > 0
        || counts.memoryRegionCount > 0
        || counts.networkEndpointCount > 0
        || counts.yaraRuleCount > 0;
    })
    .sort((left, right) => {
      const severityDifference = severityRank(right.severity ?? "") - severityRank(left.severity ?? "");
      if (severityDifference !== 0) return severityDifference;
      if (right.score !== left.score) return right.score - left.score;
      const richnessDifference = evidenceRichness(right) - evidenceRichness(left);
      if (richnessDifference !== 0) return richnessDifference;
      return left.pid - right.pid;
    });

  return filteredGroups.slice(0, limit ?? 8);
}

function plural(value: number, label: string): string {
  return `${value} ${label}${value === 1 ? "" : "s"}`;
}

function SignalCard({
  count,
  label,
  samples,
}: {
  count: number;
  label: string;
  samples: string[];
}) {
  if (count === 0 && samples.length === 0) return null;

  return (
    <div className="evidence-signal-card">
      <div className="evidence-signal-header">
        <span>{label}</span>
        <strong>{count}</strong>
      </div>
      {samples.length > 0 && (
        <div className="evidence-chip-list">
          {samples.map((sample) => <span className="evidence-chip" key={sample}>{sample}</span>)}
        </div>
      )}
    </div>
  );
}

export function MemoryEvidenceGraph(props: MemoryEvidenceGraphProps) {
  const groups = buildRelationshipGroups(props);
  const note = props.focusPid === null
    ? "Showing top process-linked relationships from loaded RAMSight records. These are triage signals and require analyst review."
    : `Showing process-linked relationships for Focus PID ${props.focusPid}. These signals support investigation and are not conclusive by themselves.`;

  if (groups.length === 0) {
    return (
      <div className="page-stack compact-stack">
        <p className="section-note">{note}</p>
        <p className="muted">No process-linked memory-only relationships were available for this job.</p>
      </div>
    );
  }

  return (
    <div className="evidence-graph">
      <p className="section-note">{note}</p>
      {groups.map((group) => {
        const counts = countFromGroup(group);
        const iocTypeSamples = [...group.iocTypeCounts.entries()]
          .sort(([leftType], [rightType]) => leftType.localeCompare(rightType))
          .map(([type, count]) => `${type}: ${count}`);
        const iocSamples = [...new Set([...iocTypeSamples, ...group.iocSamples])].slice(0, 5);

        return (
          <article className="evidence-graph-row" key={group.key}>
            <div className="evidence-process-node">
              <div className="evidence-process-heading">
                <Badge tone={statusTone(group.severity ?? "neutral")}>{group.severity ?? "context"}</Badge>
                <span>{group.score > 0 ? `Score ${group.score}` : "Score N/A"}</span>
              </div>
              <strong>{group.processName ?? "Process name not recorded"}</strong>
              <code className="code-value">PID {group.pid}</code>
              <span className="muted">{plural(counts.findingCount, "related finding")}</span>
            </div>

            <div className="evidence-relationship-connector" aria-hidden="true" />

            <div className="evidence-signal-grid">
              <SignalCard
                count={counts.memoryRegionCount}
                label="Memory regions"
                samples={[...group.memoryRegionSamples].slice(0, 3)}
              />
              <SignalCard
                count={counts.yaraRuleCount}
                label="YARA rules"
                samples={[...group.yaraRules].slice(0, 4)}
              />
              <SignalCard
                count={counts.iocCount}
                label="IOC records"
                samples={iocSamples}
              />
              <SignalCard
                count={counts.networkEndpointCount}
                label="Network endpoints"
                samples={[...group.networkEndpoints].slice(0, 3)}
              />
              <SignalCard
                count={counts.findingCount}
                label="Triage findings"
                samples={[]}
              />
            </div>
          </article>
        );
      })}
    </div>
  );
}
