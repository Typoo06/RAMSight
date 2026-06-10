import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { getAnalysisJob, getAnalysisJobStatus } from "../api/analysisJobs";
import {
  listCommandArtifacts,
  listMemoryRegionArtifacts,
  listModuleArtifacts,
  listNetworkArtifacts,
  listProcessArtifacts,
  listYaraMatches,
} from "../api/artifacts";
import { iocExportDownloadUrl, listIOCs } from "../api/iocs";
import { listPluginResults } from "../api/pluginResults";
import { listReports } from "../api/reports";
import { listRiskFindings } from "../api/riskFindings";
import { ArtifactDrilldown, MemoryRegionTable, YaraMatchTable } from "../components/results/ArtifactDrilldown";
import { FindingTable } from "../components/results/FindingTable";
import { IocTable } from "../components/results/IocTable";
import { MemoryEvidenceGraph } from "../components/results/MemoryEvidenceGraph";
import { PluginResultTable } from "../components/results/PluginResultTable";
import { ReportSection } from "../components/results/ReportSection";
import { ResultSection } from "../components/results/ResultSection";
import { Badge } from "../components/ui/Badge";
import { Card } from "../components/ui/Card";
import { ErrorState } from "../components/ui/ErrorState";
import { LoadingState } from "../components/ui/LoadingState";
import { Table } from "../components/ui/Table";
import type {
  AnalysisJob,
  CommandArtifact,
  IOC,
  MemoryRegionArtifact,
  ModuleArtifact,
  NetworkArtifact,
  PluginResult,
  ProcessArtifact,
  Report,
  RiskFinding,
  YaraMatchArtifact,
} from "../types/domain";
import { displayValue, formatDateTime, formatDurationMs } from "../utils/format";
import {
  isMemoryRegionFinding,
  isMemoryRegionIOC,
  isModuleOrPathFinding,
  isModuleOrPathIOC,
  isNetworkFinding,
  isNetworkIOC,
  isProcessRiskSummary,
  isYaraFinding,
  isYaraIOC,
  severityRank,
  sortFindingsByRisk,
} from "../utils/results";
import { isActiveJobStatus, statusTone } from "../utils/status";
import type { BadgeTone } from "../utils/status";

function terminalResultEmptyMessage(jobStatus: string, completedMessage: string): string {
  const normalized = jobStatus.toLowerCase();
  if (isActiveJobStatus(jobStatus)) {
    return "RAMSight is still running this analysis. Results will appear as the worker finishes each stage.";
  }
  if (normalized === "failed") {
    return "This analysis failed before RAMSight produced records for this section. Review the job error and worker logs for the root cause.";
  }
  if (normalized === "cancelled" || normalized === "canceled") {
    return "This analysis was cancelled before records were produced for this section.";
  }
  return completedMessage;
}

const YARA_PLUGIN_NAMES = new Set(["windows.vadyarascan", "yarascan", "linux.vmayarascan"]);

const PROFILE_LABELS: Record<string, string> = {
  windows_default: "Standard Windows triage",
  windows_memory_yara: "Elastic YARA (compatibility alias)",
  windows_memory_yara_elastic: "Windows memory + Elastic YARA",
  windows_memory_yara_neo23x0: "Windows memory + Neo23x0 YARA",
  windows_memory_yara_third_party_all: "Third-party YARA All (slow)",
  windows_memory_deep: "Deep Windows memory triage",
  windows_memory_deep_yara_elastic: "Deep memory + Elastic YARA",
  windows_memory_deep_yara_neo23x0: "Deep memory + Neo23x0 YARA",
  windows_memory_deep_yara_third_party_all: "Deep memory + Third-party YARA All (very slow)",
  windows_malware_evasion: "Windows malware evasion scan",
  windows_kernel_rootkit: "Windows kernel/rootkit scan",
  windows_investigation_context: "Windows investigation context scan",
};
const YARA_PROFILE_NAMES = new Set([
  "windows_memory_yara",
  "windows_memory_yara_elastic",
  "windows_memory_yara_neo23x0",
  "windows_memory_yara_third_party_all",
  "windows_memory_deep_yara_elastic",
  "windows_memory_deep_yara_neo23x0",
  "windows_memory_deep_yara_third_party_all",
]);

function analysisProfileLabel(profile: string | null | undefined): string {
  const normalized = normalizedPluginProfile(profile);
  if (!normalized) return "No profile recorded";
  return PROFILE_LABELS[normalized] ?? profile ?? "No profile recorded";
}

function normalizedPluginProfile(profile: string | null | undefined): string | null {
  const normalized = (profile ?? "").trim().toLowerCase();
  if (!normalized || normalized === "not recorded") return null;
  return normalized;
}

function pluginResultName(pluginResult: PluginResult): string {
  return (pluginResult.plugin_name || pluginResult.source_plugin || "").trim();
}

function isYaraPluginResult(pluginResult: PluginResult): boolean {
  const extraData = asRecord(pluginResult.extra_data);
  return YARA_PLUGIN_NAMES.has(pluginResultName(pluginResult)) || extraData.is_yara_plugin === true;
}

function timeoutSeconds(pluginResult: PluginResult): number | null {
  const value = asRecord(pluginResult.extra_data).timeout_seconds;
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function isTimedOutPlugin(pluginResult: PluginResult): boolean {
  const extraData = asRecord(pluginResult.extra_data);
  return extraData.timed_out === true
    || extraData.timeout_reason === "plugin_timeout"
    || (pluginResult.error_message ?? "").toLowerCase().includes("timed out");
}

function yaraStatusMessage(job: AnalysisJob, pluginResults: PluginResult[], hasYaraResults: boolean): string {
  const yaraPluginResults = pluginResults.filter(isYaraPluginResult);
  const timedOut = yaraPluginResults.find((pluginResult) => pluginResult.status.toLowerCase() === "failed" && isTimedOutPlugin(pluginResult));
  if (timedOut) {
    const timeout = timeoutSeconds(timedOut);
    return timeout === null
      ? `YARA scanning was selected, but ${pluginResultName(timedOut)} timed out. Other completed plugin results remain available for triage.`
      : `YARA scanning was selected, but ${pluginResultName(timedOut)} timed out after ${timeout} seconds. Other completed plugin results remain available for triage.`;
  }

  const failed = yaraPluginResults.find((pluginResult) => pluginResult.status.toLowerCase() === "failed");
  if (failed) return `YARA scanning was selected, but ${pluginResultName(failed)} failed. ${failed.error_message || "No detailed error was recorded."}`;

  const skipped = yaraPluginResults.find((pluginResult) => pluginResult.status.toLowerCase() === "skipped");
  if (skipped) return `YARA scanning was selected, but ${pluginResultName(skipped)} was skipped. ${skipped.error_message || "No detailed skip reason was recorded."}`;

  const completed = yaraPluginResults.find((pluginResult) => pluginResult.status.toLowerCase() === "completed");
  if (completed && hasYaraResults) return "YARA scanning completed and YARA-related results are available below.";
  if (completed) return "YARA scanning completed; no YARA match artifacts or YARA IOC records were recorded. This is a triage result, not a guarantee that process memory is clean.";

  const pluginProfile = normalizedPluginProfile(job.plugin_profile);
  if (!pluginProfile) return "No YARA profile was recorded for this job.";
  if (pluginProfile === "windows_default") return "YARA was not selected for this analysis profile.";
  if (YARA_PROFILE_NAMES.has(pluginProfile)) {
    return "YARA was requested, but YARA plugin status is not available through the current results APIs.";
  }
  return "YARA status is not available for this analysis profile.";
}

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return value as Record<string, unknown>;
}

function textValue(value: unknown, fallback = "Not recorded"): string {
  if (value === null || value === undefined) return fallback;
  if (Array.isArray(value)) return value.map((item) => textValue(item, "")).filter(Boolean).join(", ") || fallback;
  if (typeof value === "object") return fallback;
  const text = String(value).trim();
  return text || fallback;
}

function arrayText(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((item) => textValue(item, "")).filter(Boolean);
}

function copyToClipboard(value: unknown): void {
  const text = textValue(value, "");
  if (!text || !navigator.clipboard) return;
  void navigator.clipboard.writeText(text);
}

function CopyButton({ value, label = "Copy" }: { value: unknown; label?: string }) {
  const text = textValue(value, "");
  if (!text) return null;
  return (
    <button className="copy-button" type="button" onClick={() => copyToClipboard(text)} aria-label={`${label}: ${text}`}>
      {label}
    </button>
  );
}

function confidenceTone(confidence: string): BadgeTone {
  if (confidence === "probable_malware") return "danger";
  if (confidence === "context_only") return "neutral";
  return "warning";
}

function numericPid(value: unknown): number | null {
  if (typeof value === "number" && Number.isInteger(value)) return value;
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!/^\d+$/.test(trimmed)) return null;
  return Number(trimmed);
}

function pidFromFinding(finding: RiskFinding): number | null {
  const extraData = asRecord(finding.extra_data);
  return numericPid(extraData.pid);
}

function addressRange(region: MemoryRegionArtifact): string {
  if (region.start_address && region.end_address) return `${region.start_address}-${region.end_address}`;
  return "Not recorded";
}

function networkEndpoint(network: NetworkArtifact): string {
  const remote = network.remote_address ? `${network.remote_address}:${network.remote_port ?? ""}` : "remote unknown";
  return remote;
}

function iocRole(ioc: IOC): string {
  return textValue(asRecord(ioc.extra_data).ioc_role, "investigation_artifact");
}

interface PluginCoverageRow {
  category: string;
  selected: number;
  completed: number;
  failed: number;
  skipped: number;
  unavailable: number;
  plugins: string[];
}

function buildPluginCoverage(pluginResults: PluginResult[]): PluginCoverageRow[] {
  const grouped = new Map<string, PluginCoverageRow>();
  for (const pluginResult of pluginResults) {
    const extraData = asRecord(pluginResult.extra_data);
    const category = textValue(extraData.plugin_category, "Core triage");
    const bucket = grouped.get(category) ?? {
      category,
      selected: 0,
      completed: 0,
      failed: 0,
      skipped: 0,
      unavailable: 0,
      plugins: [],
    };
    const status = pluginResult.status.toLowerCase();
    bucket.selected += 1;
    if (status === "completed") bucket.completed += 1;
    if (status === "failed") bucket.failed += 1;
    if (status === "skipped") bucket.skipped += 1;
    if (extraData.available === false || status === "unavailable") bucket.unavailable += 1;
    bucket.plugins.push(pluginResult.plugin_name);
    grouped.set(category, bucket);
  }
  const order = [
    "Core triage",
    "Memory/VAD",
    "Injection/Hollowing",
    "Thread analysis",
    "YARA",
    "Network",
    "Module/DLL",
    "Evasion/Hooking",
    "Kernel/Rootkit",
    "Persistence/Context",
  ];
  return [...grouped.values()].sort((left, right) => {
    const leftIndex = order.indexOf(left.category);
    const rightIndex = order.indexOf(right.category);
    return (leftIndex === -1 ? 999 : leftIndex) - (rightIndex === -1 ? 999 : rightIndex) || left.category.localeCompare(right.category);
  });
}

function TopActionableDetections({
  findings,
  memoryRegions,
  networkArtifacts,
  yaraMatches,
  onFindingUpdated,
}: {
  findings: RiskFinding[];
  memoryRegions: MemoryRegionArtifact[];
  networkArtifacts: NetworkArtifact[];
  yaraMatches: YaraMatchArtifact[];
  onFindingUpdated: (finding: RiskFinding) => void;
}) {
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const visibleFindings = findings.slice(0, 10);

  return (
    <div className="actionable-list">
      {visibleFindings.map((finding) => {
        const extraData = asRecord(finding.extra_data);
        const pid = pidFromFinding(finding);
        const confidence = textValue(extraData.detection_confidence || extraData.finding_intent, "suspicious");
        const evidenceGroups = arrayText(extraData.evidence_groups);
        const yaraRules = arrayText(extraData.yara_rules).slice(0, 8);
        const pidMemoryRegions = pid === null ? [] : memoryRegions.filter((region) => region.pid === pid).slice(0, 5);
        const pidNetworks = pid === null ? [] : networkArtifacts.filter((network) => network.pid === pid && network.remote_address).slice(0, 5);
        const pidYaraRules = pid === null ? [] : [...new Set(yaraMatches
          .filter((match) => pidFromTargetIdentifier(match.target_identifier) === pid)
          .map((match) => match.rule_name)
          .filter(Boolean))]
          .slice(0, 8);
        const displayedRules = yaraRules.length > 0 ? yaraRules : pidYaraRules;
        const expanded = expandedFindingId === finding.id;
        const commandLine = textValue(extraData.command_line, "");

        return (
          <article className={`actionable-card verdict-${confidence}`} key={finding.id}>
            <div className="actionable-header">
              <div>
                <h3>{textValue(extraData.process_name, finding.title)} {pid !== null && <span className="muted">(PID {pid})</span>}</h3>
                <p className="muted">{finding.title}</p>
              </div>
              <div className="actionable-badges">
                <Badge tone={statusTone(finding.effective_severity ?? finding.severity)}>{finding.effective_severity ?? finding.severity}</Badge>
                <Badge tone={confidenceTone(confidence)}>{confidence.replaceAll("_", " ")}</Badge>
              </div>
            </div>

            <dl className="actionable-meta">
              <div><dt>Score</dt><dd>{finding.score}</dd></div>
              <div><dt>PID</dt><dd>{pid ?? "Not recorded"} <CopyButton value={pid} /></dd></div>
              <div><dt>Image path</dt><dd><code>{textValue(extraData.image_path)}</code> <CopyButton value={extraData.image_path} /></dd></div>
              <div><dt>Evidence</dt><dd>{evidenceGroups.length > 0 ? evidenceGroups.join(", ") : "Not recorded"}</dd></div>
            </dl>

            {commandLine && (
              <div className="evidence-line">
                <strong>Command line</strong>
                <code>{commandLine}</code>
                <CopyButton value={commandLine} label="Copy command" />
              </div>
            )}

            <div className="evidence-pill-row">
              {displayedRules.map((rule) => (
                <span className="evidence-pill" key={rule}>YARA: {rule} <CopyButton value={rule} /></span>
              ))}
              {pidMemoryRegions.map((region) => (
                <span className="evidence-pill" key={region.id}>Region: {addressRange(region)} <CopyButton value={addressRange(region)} /></span>
              ))}
              {pidNetworks.map((network) => (
                <span className="evidence-pill" key={network.id}>Endpoint: {networkEndpoint(network)} <CopyButton value={networkEndpoint(network)} /></span>
              ))}
            </div>

            <p className="recommendation-text">{textValue(finding.recommendation)}</p>

            <details className="evidence-details" open={expanded} onToggle={(event) => setExpandedFindingId(event.currentTarget.open ? finding.id : null)}>
              <summary>Evidence chain and review controls</summary>
              <div className="evidence-detail-grid">
                <div>
                  <h4>YARA rules</h4>
                  {displayedRules.length > 0 ? displayedRules.map((rule) => <p key={rule}><code>{rule}</code> <CopyButton value={rule} /></p>) : <p className="muted">Not recorded</p>}
                </div>
                <div>
                  <h4>Memory regions</h4>
                  {pidMemoryRegions.length > 0 ? pidMemoryRegions.map((region) => <p key={region.id}><code>{addressRange(region)}</code> {textValue(region.protection, "")} <CopyButton value={addressRange(region)} /></p>) : <p className="muted">Not recorded in loaded rows</p>}
                </div>
                <div>
                  <h4>Network endpoints</h4>
                  {pidNetworks.length > 0 ? pidNetworks.map((network) => <p key={network.id}><code>{networkEndpoint(network)}</code> {textValue(network.state, "")} <CopyButton value={networkEndpoint(network)} /></p>) : <p className="muted">Not recorded in loaded rows</p>}
                </div>
              </div>
              <FindingTable caption="Underlying process summary row" findings={[finding]} limit={1} onFindingUpdated={onFindingUpdated} />
            </details>
          </article>
        );
      })}
      {findings.length > visibleFindings.length && <p className="table-note">Showing {visibleFindings.length} of {findings.length} process-level detections. Use the process summary table for the rest.</p>}
    </div>
  );
}

function pidFromTargetIdentifier(value: string | null | undefined): number | null {
  if (!value) return null;
  const trimmed = value.trim();
  const exact = trimmed.match(/^\d+$/);
  if (exact) return Number(exact[0]);
  const pidLabel = trimmed.match(/^pid\s+(\d+)$/i);
  return pidLabel ? Number(pidLabel[1]) : null;
}

function collectPidOptions(
  findings: RiskFinding[],
  processes: ProcessArtifact[],
  commands: CommandArtifact[],
  networks: NetworkArtifact[],
  modules: ModuleArtifact[],
  memoryRegions: MemoryRegionArtifact[],
  yaraMatches: YaraMatchArtifact[],
): number[] {
  const values = new Set<number>();
  for (const finding of findings) {
    const extraData = asRecord(finding.extra_data);
    const linkedArtifacts = asRecord(extraData.linked_artifacts);
    const pid = numericPid(extraData.pid) ?? numericPid(linkedArtifacts.pid);
    if (pid !== null) values.add(pid);
  }
  for (const row of [...processes, ...commands, ...networks, ...modules, ...memoryRegions]) {
    if (row.pid !== null) values.add(row.pid);
  }
  for (const match of yaraMatches) {
    const extraData = asRecord(match.extra_data);
    const pid = numericPid(extraData.pid) ?? numericPid(extraData.process_id) ?? pidFromTargetIdentifier(match.target_identifier);
    if (pid !== null) values.add(pid);
  }
  return [...values].sort((left, right) => left - right);
}

export function AnalysisJobStatusPage() {
  const { caseId, jobId } = useParams();
  const [error, setError] = useState<string | null>(null);
  const [commandArtifacts, setCommandArtifacts] = useState<CommandArtifact[]>([]);
  const [drilldownError, setDrilldownError] = useState<string | null>(null);
  const [drilldownLoading, setDrilldownLoading] = useState(true);
  const [findingError, setFindingError] = useState<string | null>(null);
  const [findingLoading, setFindingLoading] = useState(true);
  const [findings, setFindings] = useState<RiskFinding[]>([]);
  const [focusPidText, setFocusPidText] = useState("");
  const [iocError, setIocError] = useState<string | null>(null);
  const [iocLoading, setIocLoading] = useState(true);
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [job, setJob] = useState<AnalysisJob | null>(null);
  const [loading, setLoading] = useState(true);
  const [memoryRegions, setMemoryRegions] = useState<MemoryRegionArtifact[]>([]);
  const [moduleArtifacts, setModuleArtifacts] = useState<ModuleArtifact[]>([]);
  const [networkArtifacts, setNetworkArtifacts] = useState<NetworkArtifact[]>([]);
  const [pluginResults, setPluginResults] = useState<PluginResult[]>([]);
  const [processArtifacts, setProcessArtifacts] = useState<ProcessArtifact[]>([]);
  const [reportError, setReportError] = useState<string | null>(null);
  const [reportLoading, setReportLoading] = useState(true);
  const [reports, setReports] = useState<Report[]>([]);
  const [reviewStatusFilter, setReviewStatusFilter] = useState("all");
  const [yaraMatches, setYaraMatches] = useState<YaraMatchArtifact[]>([]);
  const reviewStatusParam = reviewStatusFilter === "all" ? undefined : reviewStatusFilter;

  useEffect(() => {
    if (!jobId) return;
    let active = true;
    getAnalysisJob(jobId)
      .then((item) => {
        if (active) setJob(item);
      })
      .catch((err: unknown) => {
        if (active) setError(err instanceof Error ? err.message : "RAMSight could not load this analysis job.");
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [jobId]);

  const focusPid = useMemo(() => {
    const trimmed = focusPidText.trim();
    if (!trimmed) return null;
    const pid = numericPid(trimmed);
    return pid !== null && pid >= 0 ? pid : null;
  }, [focusPidText]);
  const focusPidError = "Focus PID must be a non-negative integer.";
  const focusPidInvalid = focusPidText.trim() !== "" && focusPid === null;
  const drilldownSectionLoading = focusPidInvalid ? false : drilldownLoading;
  const drilldownSectionError = focusPidInvalid ? focusPidError : drilldownError;

  useEffect(() => {
    if (!jobId) return;
    if (focusPidInvalid) return;

    let active = true;
    const artifactFilters = focusPid === null ? { limit: 100 } : { pid: focusPid, limit: 100 };

    Promise.resolve().then(() => {
      if (!active) return null;
      setDrilldownLoading(true);
      setDrilldownError(null);
      return Promise.allSettled([
      listPluginResults(jobId, { limit: 100 }),
      listProcessArtifacts(jobId, artifactFilters),
      listCommandArtifacts(jobId, artifactFilters),
      listNetworkArtifacts(jobId, artifactFilters),
      listModuleArtifacts(jobId, artifactFilters),
      listMemoryRegionArtifacts(jobId, artifactFilters),
      listYaraMatches(jobId, artifactFilters),
      ]);
    }).then((results) => {
      if (!results) return;
      if (!active) return;
      const [pluginResult, processResult, commandResult, networkResult, moduleResult, memoryResult, yaraResult] = results;
      const errors: string[] = [];

      if (pluginResult.status === "fulfilled") setPluginResults(pluginResult.value.items);
      else errors.push(pluginResult.reason instanceof Error ? pluginResult.reason.message : "RAMSight could not load plugin results.");

      if (processResult.status === "fulfilled") setProcessArtifacts(processResult.value.items);
      else errors.push(processResult.reason instanceof Error ? processResult.reason.message : "RAMSight could not load process artifacts.");

      if (commandResult.status === "fulfilled") setCommandArtifacts(commandResult.value.items);
      else errors.push(commandResult.reason instanceof Error ? commandResult.reason.message : "RAMSight could not load command artifacts.");

      if (networkResult.status === "fulfilled") setNetworkArtifacts(networkResult.value.items);
      else errors.push(networkResult.reason instanceof Error ? networkResult.reason.message : "RAMSight could not load network artifacts.");

      if (moduleResult.status === "fulfilled") setModuleArtifacts(moduleResult.value.items);
      else errors.push(moduleResult.reason instanceof Error ? moduleResult.reason.message : "RAMSight could not load module artifacts.");

      if (memoryResult.status === "fulfilled") setMemoryRegions(memoryResult.value.items);
      else errors.push(memoryResult.reason instanceof Error ? memoryResult.reason.message : "RAMSight could not load memory region artifacts.");

      if (yaraResult.status === "fulfilled") setYaraMatches(yaraResult.value.items);
      else errors.push(yaraResult.reason instanceof Error ? yaraResult.reason.message : "RAMSight could not load YARA match artifacts.");

      setDrilldownError(errors[0] ?? null);
      setDrilldownLoading(false);
    });

    return () => {
      active = false;
    };
  }, [focusPid, focusPidInvalid, job?.status, jobId]);

  useEffect(() => {
    if (!jobId || !job || isActiveJobStatus(job.status)) return;
    let active = true;

    Promise.allSettled([
      listRiskFindings({ job_id: jobId, review_status: reviewStatusParam, limit: 500 }),
      listIOCs({ job_id: jobId, limit: 500 }),
      listReports({ job_id: jobId, limit: 100 }),
    ]).then(([findingResult, iocResult, reportResult]) => {
      if (!active) return;

      if (findingResult.status === "fulfilled") {
        setFindings(findingResult.value.items);
      } else {
        setFindingError(findingResult.reason instanceof Error ? findingResult.reason.message : "RAMSight could not refresh risk findings.");
      }

      if (iocResult.status === "fulfilled") {
        setIocs(iocResult.value.items);
      } else {
        setIocError(iocResult.reason instanceof Error ? iocResult.reason.message : "RAMSight could not refresh IOC records.");
      }

      if (reportResult.status === "fulfilled") {
        setReports(reportResult.value.items.filter((report) => report.format === "html"));
      } else {
        setReportError(reportResult.reason instanceof Error ? reportResult.reason.message : "RAMSight could not refresh report metadata.");
      }
    });

    return () => {
      active = false;
    };
  }, [jobId, job, reviewStatusParam]);

  useEffect(() => {
    if (!jobId) return;
    let active = true;

    Promise.resolve().then(() => {
      if (!active) return null;
      setFindingLoading(true);
      return listRiskFindings({ job_id: jobId, review_status: reviewStatusParam, limit: 500 });
    })
      .then((response) => {
        if (!response) return;
        if (active) setFindings(response.items);
      })
      .catch((err: unknown) => {
        if (active) setFindingError(err instanceof Error ? err.message : "RAMSight could not load risk findings.");
      })
      .finally(() => {
        if (active) setFindingLoading(false);
      });

    listIOCs({ job_id: jobId, limit: 500 })
      .then((response) => {
        if (active) setIocs(response.items);
      })
      .catch((err: unknown) => {
        if (active) setIocError(err instanceof Error ? err.message : "RAMSight could not load IOC records.");
      })
      .finally(() => {
        if (active) setIocLoading(false);
      });

    listReports({ job_id: jobId, limit: 100 })
      .then((response) => {
        if (active) setReports(response.items.filter((report) => report.format === "html"));
      })
      .catch((err: unknown) => {
        if (active) setReportError(err instanceof Error ? err.message : "RAMSight could not load report metadata.");
      })
      .finally(() => {
        if (active) setReportLoading(false);
      });

    return () => {
      active = false;
    };
  }, [jobId, reviewStatusParam]);

  useEffect(() => {
    if (!job?.id || !isActiveJobStatus(job.status)) return;
    let active = true;
    const intervalId = window.setInterval(() => {
      getAnalysisJobStatus(job.id)
        .then((status) => {
          if (active) setJob((current) => (current ? { ...current, ...status } : current));
        })
        .catch((err: unknown) => {
          if (active) setError(err instanceof Error ? err.message : "RAMSight could not refresh job status.");
        });
    }, 3000);
    return () => {
      active = false;
      window.clearInterval(intervalId);
    };
  }, [job?.id, job?.status]);

  const sortedFindings = useMemo(() => sortFindingsByRisk(findings), [findings]);
  const highPriorityFindings = useMemo(
    () => sortedFindings.filter((finding) => severityRank(finding.effective_severity ?? finding.severity) >= severityRank("high")),
    [sortedFindings],
  );
  function handleFindingUpdated(updatedFinding: RiskFinding) {
    setFindings((current) => {
      const updatedStatus = updatedFinding.review_status || "new";
      if (reviewStatusParam && updatedStatus !== reviewStatusParam) {
        return current.filter((finding) => finding.id !== updatedFinding.id);
      }
      return current.map((finding) => (finding.id === updatedFinding.id ? updatedFinding : finding));
    });
  }
  const processRiskSummaries = useMemo(() => sortedFindings.filter(isProcessRiskSummary), [sortedFindings]);
  const networkFindings = useMemo(() => sortedFindings.filter(isNetworkFinding), [sortedFindings]);
  const moduleFindings = useMemo(() => sortedFindings.filter(isModuleOrPathFinding), [sortedFindings]);
  const memoryFindings = useMemo(() => sortedFindings.filter(isMemoryRegionFinding), [sortedFindings]);
  const yaraFindings = useMemo(() => sortedFindings.filter(isYaraFinding), [sortedFindings]);
  const supportingFindings = useMemo(() => sortedFindings.filter((finding) => !isProcessRiskSummary(finding)), [sortedFindings]);
  const networkIocs = useMemo(() => iocs.filter(isNetworkIOC), [iocs]);
  const moduleIocs = useMemo(() => iocs.filter(isModuleOrPathIOC), [iocs]);
  const memoryIocs = useMemo(() => iocs.filter(isMemoryRegionIOC), [iocs]);
  const yaraIocs = useMemo(() => iocs.filter(isYaraIOC), [iocs]);
  const threatIocs = useMemo(() => iocs.filter((ioc) => iocRole(ioc) === "threat_ioc"), [iocs]);
  const investigationArtifactIocs = useMemo(() => iocs.filter((ioc) => iocRole(ioc) !== "threat_ioc"), [iocs]);
  const yaraMessage = job ? yaraStatusMessage(job, pluginResults, yaraFindings.length > 0 || yaraIocs.length > 0 || yaraMatches.length > 0) : "No YARA profile was recorded for this job.";
  const pidOptions = useMemo(
    () => collectPidOptions(findings, processArtifacts, commandArtifacts, networkArtifacts, moduleArtifacts, memoryRegions, yaraMatches),
    [commandArtifacts, findings, memoryRegions, moduleArtifacts, networkArtifacts, processArtifacts, yaraMatches],
  );
  const focusedArtifactCount = processArtifacts.length + commandArtifacts.length + networkArtifacts.length + moduleArtifacts.length + memoryRegions.length + yaraMatches.length;
  const completedPluginCount = pluginResults.filter((pluginResult) => pluginResult.status.toLowerCase() === "completed").length;
  const failedPluginCount = pluginResults.filter((pluginResult) => pluginResult.status.toLowerCase() === "failed").length;
  const pluginSummaryValue = pluginResults.length === 0 ? "Pending" : `${completedPluginCount}/${pluginResults.length}`;
  const pluginSummaryDetail = pluginResults.length === 0
    ? "Plugin metadata has not loaded yet"
    : failedPluginCount === 0
      ? "Completed plugins"
      : `${failedPluginCount} plugin issue${failedPluginCount === 1 ? "" : "s"} recorded`;
  const reportSummaryDetail = reports.length === 0 ? "No HTML report metadata yet" : "HTML report metadata available";
  const pluginCoverage = useMemo(() => buildPluginCoverage(pluginResults), [pluginResults]);
  const relationshipInputWarning = findingError || iocError || drilldownSectionError
    ? "Some relationship inputs are unavailable. RAMSight is showing loaded metadata only."
    : null;
  const iocExportActions = job ? (
    <div className="button-row">
      <a className="button button-secondary button-small" href={iocExportDownloadUrl(job.id, "json")}>Download IOC JSON</a>
      <a className="button button-secondary button-small" href={iocExportDownloadUrl(job.id, "csv")}>Download IOC CSV</a>
    </div>
  ) : null;

  if (!caseId || !jobId) return <ErrorState message="RAMSight could not identify the requested analysis job." />;
  if (loading) return <LoadingState label="Loading RAMSight analysis job..." />;
  if (error && !job) return <ErrorState message={error} />;
  if (!job) return <ErrorState message="RAMSight did not return analysis job metadata." />;

  return (
    <div className="page-stack">
      <section className="page-heading page-heading-row">
        <div>
          <span className="eyebrow">Analysis results</span>
          <h2>RAMSight job monitor</h2>
          <p>{job.id}</p>
        </div>
        <Badge tone={statusTone(job.status)}>{job.status}</Badge>
      </section>

      {error && <ErrorState message={error} title="Status refresh warning" />}

      <div className="detail-grid">
        <Card title="Job timeline">
          <dl className="metadata-list">
            <div><dt>Status</dt><dd><Badge tone={statusTone(job.status)}>{job.status}</Badge></dd></div>
            <div><dt>Duration</dt><dd>{formatDurationMs(job.duration_ms)}</dd></div>
            <div><dt>Created</dt><dd>{formatDateTime(job.created_at)}</dd></div>
            <div><dt>Updated</dt><dd>{formatDateTime(job.updated_at)}</dd></div>
            <div><dt>Started</dt><dd>{formatDateTime(job.started_at)}</dd></div>
            <div><dt>Completed</dt><dd>{formatDateTime(job.completed_at)}</dd></div>
          </dl>
          {job.error_message && <p className="error-text">{job.error_message}</p>}
        </Card>

        <Card title="Analysis profile">
          <dl className="metadata-list metadata-list-single">
            <div><dt>OS family</dt><dd>{displayValue(job.os_family)}</dd></div>
            <div><dt>OS version</dt><dd>{displayValue(job.os_version)}</dd></div>
            <div><dt>Architecture</dt><dd>{displayValue(job.architecture)}</dd></div>
            <div><dt>Kernel version</dt><dd>{displayValue(job.kernel_version)}</dd></div>
            <div><dt>Symbol table</dt><dd>{displayValue(job.symbol_table)}</dd></div>
            <div><dt>Plugin profile</dt><dd><strong>{analysisProfileLabel(job.plugin_profile)}</strong><span className="table-subtext">{displayValue(job.plugin_profile)}</span></dd></div>
          </dl>
        </Card>
      </div>

      {job.status.toLowerCase() === "failed" && (
        <Card className="status-callout status-callout-danger" title="Analysis failed">
          <p>{job.error_message || "RAMSight marked this job failed, but no detailed error message was recorded."}</p>
          <p className="muted">The case and evidence metadata are still available. Result sections below may be empty if the worker failed before parsing, detection, IOC extraction, or report generation completed.</p>
        </Card>
      )}

      <div className="dashboard-grid">
        <Card title="Findings"><p className="metric-value">{findings.length}</p><p className="muted">Triage findings recorded</p></Card>
        <Card title="High priority"><p className="metric-value">{highPriorityFindings.length}</p><p className="muted">High or critical findings</p></Card>
        <Card title="Indicators"><p className="metric-value">{iocs.length}</p><p className="muted">Extracted IOC records</p></Card>
        <Card title="Plugin completion"><p className="metric-value metric-value-text">{pluginSummaryValue}</p><p className="muted">{pluginSummaryDetail}</p></Card>
        <Card title="Reports"><p className="metric-value">{reports.length}</p><p className="muted">{reportSummaryDetail}</p></Card>
      </div>

      <div className="detail-grid">
        <Card className="status-callout status-callout-info" title="YARA status">
          <p>{yaraMessage}</p>
        </Card>
        <Card className="status-callout" title="Analyst review note">
          <p>RAMSight findings are triage indicators. They support investigation and require analyst review before any conclusion is made.</p>
        </Card>
      </div>

      <Card title="Finding review filter">
        <div className="filter-row">
          <label>
            <span>Review status</span>
            <select value={reviewStatusFilter} onChange={(event) => setReviewStatusFilter(event.target.value)}>
              <option value="all">All findings</option>
              <option value="new">New</option>
              <option value="investigating">Investigating</option>
              <option value="reviewed">Reviewed</option>
            </select>
          </label>
        </div>
        <p className="muted">Review status is analyst metadata and does not change RAMSight detection records or regenerate the technical report.</p>
      </Card>

      <ResultSection
        title="Top Actionable Detections"
        loading={findingLoading}
        error={findingError}
        empty={processRiskSummaries.length === 0}
        emptyMessage={terminalResultEmptyMessage(job.status, "RAMSight completed this analysis with no risk findings recorded through the current APIs.")}
      >
        <TopActionableDetections
          findings={processRiskSummaries}
          memoryRegions={memoryRegions}
          networkArtifacts={networkArtifacts}
          onFindingUpdated={handleFindingUpdated}
          yaraMatches={yaraMatches}
        />
      </ResultSection>

      <ResultSection
        title="Supporting risk findings"
        loading={findingLoading}
        error={findingError}
        empty={supportingFindings.length === 0}
        emptyMessage={terminalResultEmptyMessage(job.status, "RAMSight completed this analysis with no supporting risk findings recorded through the current APIs.")}
      >
        <FindingTable caption="Supporting raw and deduplicated findings; process-level summaries are shown above" findings={supportingFindings} limit={20} onFindingUpdated={handleFindingUpdated} />
      </ResultSection>

      <ResultSection
        title="Process risk summary"
        loading={findingLoading}
        error={findingError}
        empty={processRiskSummaries.length === 0}
        emptyMessage={terminalResultEmptyMessage(job.status, "No process risk summary findings are available for this job.")}
      >
        <FindingTable caption="Process-level risk summaries" findings={processRiskSummaries} limit={20} onFindingUpdated={handleFindingUpdated} />
      </ResultSection>

      <ResultSection
        title="Memory-only Evidence Relationships"
        loading={findingLoading || iocLoading || drilldownSectionLoading}
        empty={false}
      >
        <div className="page-stack compact-stack">
          {relationshipInputWarning && <p className="table-note">{relationshipInputWarning}</p>}
          <MemoryEvidenceGraph
            findings={sortedFindings}
            focusPid={focusPidInvalid ? null : focusPid}
            iocs={iocs}
            memoryRegions={memoryRegions}
            networkArtifacts={networkArtifacts}
            processArtifacts={processArtifacts}
            yaraMatches={yaraMatches}
          />
        </div>
      </ResultSection>

      <ResultSection
        title="Network indicators"
        loading={findingLoading || iocLoading}
        error={findingError || iocError}
        empty={networkFindings.length === 0 && networkIocs.length === 0}
        emptyMessage={terminalResultEmptyMessage(job.status, "No network findings or network IOC records are available for this job.")}
      >
        <div className="page-stack compact-stack">
          {networkFindings.length > 0 && <FindingTable caption="Network-related findings" findings={networkFindings} limit={20} onFindingUpdated={handleFindingUpdated} />}
          {networkIocs.length > 0 && <IocTable caption="Network IOC records" iocs={networkIocs} limit={50} />}
        </div>
      </ResultSection>

      <ResultSection
        title="Suspicious module and path indicators"
        loading={findingLoading || iocLoading}
        error={findingError || iocError}
        empty={moduleFindings.length === 0 && moduleIocs.length === 0}
        emptyMessage={terminalResultEmptyMessage(job.status, "No suspicious module or path indicators are available through the current APIs.")}
      >
        <div className="page-stack compact-stack">
          {moduleFindings.length > 0 && <FindingTable caption="Module/path findings" findings={moduleFindings} limit={20} onFindingUpdated={handleFindingUpdated} />}
          {moduleIocs.length > 0 && <IocTable caption="Module/path IOC records" iocs={moduleIocs} limit={50} />}
        </div>
      </ResultSection>

      <ResultSection
        title="Memory region findings"
        loading={findingLoading || iocLoading}
        error={findingError || iocError}
        empty={memoryFindings.length === 0 && memoryIocs.length === 0}
        emptyMessage={terminalResultEmptyMessage(job.status, "No memory region findings are available for this job.")}
      >
        <div className="page-stack compact-stack">
          {memoryFindings.length > 0 && <FindingTable caption="Memory region findings" findings={memoryFindings} limit={20} onFindingUpdated={handleFindingUpdated} />}
          {memoryIocs.length > 0 && <IocTable caption="Memory region IOC records" iocs={memoryIocs} limit={50} />}
        </div>
      </ResultSection>

      <ResultSection
        title="YARA matches"
        loading={findingLoading || iocLoading}
        error={findingError || iocError}
        empty={yaraFindings.length === 0 && yaraIocs.length === 0}
        emptyMessage={yaraMessage}
      >
        <div className="page-stack compact-stack">
          <p className="section-note">{yaraMessage}</p>
          {yaraFindings.length > 0 && <FindingTable caption="YARA-related findings" findings={yaraFindings} limit={20} onFindingUpdated={handleFindingUpdated} />}
          {yaraIocs.length > 0 && <IocTable caption="YARA IOC records" iocs={yaraIocs} limit={50} />}
        </div>
      </ResultSection>

      <ResultSection
        title="Plugin results"
        loading={drilldownSectionLoading}
        error={drilldownSectionError}
        empty={pluginResults.length === 0}
        emptyMessage={terminalResultEmptyMessage(job.status, "No plugin result metadata is available for this job.")}
      >
        <div className="page-stack compact-stack">
          {pluginCoverage.length > 0 && (
            <div className="table-block">
              <Table caption="Plugin coverage by category">
                <thead>
                  <tr><th>Category</th><th>Selected</th><th>Completed</th><th>Failed</th><th>Skipped</th><th>Unavailable</th><th>Plugins</th></tr>
                </thead>
                <tbody>
                  {pluginCoverage.map((row) => (
                    <tr key={row.category}>
                      <td>{row.category}</td>
                      <td>{row.selected}</td>
                      <td>{row.completed}</td>
                      <td>{row.failed}</td>
                      <td>{row.skipped}</td>
                      <td>{row.unavailable}</td>
                      <td className="long-text">{row.plugins.join(", ")}</td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </div>
          )}
          <PluginResultTable pluginResults={pluginResults} />
        </div>
      </ResultSection>

      <Card title="Artifact drill-down filter">
        <div className="filter-row">
          <label>
            <span>Focus PID</span>
            <input
              list="artifact-pid-options"
              inputMode="numeric"
              placeholder="Example: 340"
              value={focusPidText}
              onChange={(event) => setFocusPidText(event.target.value)}
            />
          </label>
          <button className="button button-secondary" type="button" onClick={() => setFocusPidText("")}>Clear</button>
        </div>
        <datalist id="artifact-pid-options">
          {pidOptions.map((pid) => <option key={pid} value={pid} />)}
        </datalist>
        {focusPidInvalid && <p className="error-text">{focusPidError}</p>}
        <p className="muted">Use Focus PID to inspect process, command, network, module, memory-region, and YARA artifacts for one process. RAMSight shows stored metadata only, not raw memory dump content.</p>
      </Card>

      <ResultSection
        title="Memory region detail"
        loading={drilldownSectionLoading}
        error={drilldownSectionError}
        empty={memoryRegions.length === 0}
        emptyMessage={terminalResultEmptyMessage(job.status, "No memory-region artifacts are available for this job.")}
      >
        <MemoryRegionTable caption={focusPid === null ? "Memory region artifacts" : `Memory region artifacts for PID ${focusPid}`} memoryRegions={memoryRegions} limit={50} />
      </ResultSection>

      <ResultSection
        title="YARA match detail"
        loading={drilldownSectionLoading}
        error={drilldownSectionError}
        empty={yaraMatches.length === 0}
        emptyMessage={terminalResultEmptyMessage(job.status, "No YARA match artifacts are available for this job. Check the YARA status message above before treating this as a clean no-match result.")}
      >
        <YaraMatchTable caption={focusPid === null ? "YARA match artifacts" : `YARA match artifacts for PID ${focusPid}`} yaraMatches={yaraMatches} limit={50} />
      </ResultSection>

      <ResultSection
        title="Process-centered evidence"
        loading={drilldownSectionLoading}
        error={drilldownSectionError}
        empty={focusPid !== null && focusedArtifactCount === 0}
        emptyMessage={`No normalized artifacts are available for PID ${focusPid}.`}
      >
        <ArtifactDrilldown
          commandArtifacts={commandArtifacts}
          focusPid={focusPid}
          memoryRegions={memoryRegions}
          moduleArtifacts={moduleArtifacts}
          networkArtifacts={networkArtifacts}
          processArtifacts={processArtifacts}
          yaraMatches={yaraMatches}
        />
      </ResultSection>

      <ResultSection
        title="Threat-Oriented IOCs"
        actions={iocExportActions}
        loading={iocLoading}
        error={iocError}
        empty={threatIocs.length === 0}
        emptyMessage={terminalResultEmptyMessage(job.status, "RAMSight completed this analysis with no threat-oriented IOC records extracted.")}
      >
        <div className="page-stack compact-stack">
          <IocTable caption="Threat-oriented IOC records for this analysis job" iocs={threatIocs} limit={100} />
          <p className="muted">Threat-oriented IOCs emphasize public endpoints, suspicious paths, and malware-specific YARA rules with correlation. Exports still include all stored IOC records.</p>
        </div>
      </ResultSection>

      <ResultSection
        title="Investigation Artifacts"
        loading={iocLoading}
        error={iocError}
        empty={investigationArtifactIocs.length === 0}
        emptyMessage={terminalResultEmptyMessage(job.status, "RAMSight completed this analysis with no investigation artifact IOC records extracted.")}
      >
        <div className="page-stack compact-stack">
          <IocTable caption="Contextual investigation artifacts" iocs={investigationArtifactIocs} limit={100} />
          <p className="muted">PIDs, plugin references, memory regions, and generic YARA hits are shown as investigation artifacts, not direct threat IOCs.</p>
        </div>
      </ResultSection>

      <ResultSection
        title="HTML reports"
        loading={reportLoading}
        error={reportError}
        empty={reports.length === 0}
        emptyMessage={terminalResultEmptyMessage(job.status, "No HTML report metadata is available for this job yet.")}
      >
        <ReportSection reports={reports} />
      </ResultSection>

      <Card title="Current workflow">
        <ol className="timeline-list">
          <li className={job.status === "queued" ? "timeline-current" : ""}>Queued for RAMSight worker execution</li>
          <li className={job.status === "running" ? "timeline-current" : ""}>Running memory analysis pipeline</li>
          <li className={["completed", "failed", "cancelled", "canceled"].includes(job.status.toLowerCase()) ? "timeline-current" : ""}>Terminal job state reached</li>
        </ol>
        <Link className="text-link" to={`/cases/${caseId}`}>
          Back to case detail
        </Link>
      </Card>
    </div>
  );
}
