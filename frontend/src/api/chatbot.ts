import {
  listCommandArtifacts,
  listMemoryRegionArtifacts,
  listModuleArtifacts,
  listNetworkArtifacts,
  listProcessArtifacts,
  listYaraMatches,
} from "./artifacts";
import { getAnalysisJob } from "./analysisJobs";
import { listIOCs } from "./iocs";
import { listPluginResults } from "./pluginResults";
import { listReports } from "./reports";
import { listRiskFindings } from "./riskFindings";
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

export interface ChatbotJobSummary {
  answer: string;
  jobId: string;
}

export interface ChatbotJobContext {
  job: AnalysisJob;
  reports: Report[];
  findings: RiskFinding[];
  iocs: IOC[];
  pluginResults: PluginResult[];
  processes: ProcessArtifact[];
  commands: CommandArtifact[];
  networks: NetworkArtifact[];
  modules: ModuleArtifact[];
  memoryRegions: MemoryRegionArtifact[];
  yaraMatches: YaraMatchArtifact[];
  totals: {
    findings: number;
    iocs: number;
  };
}

const JOB_ID_PATTERN = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i;

export function extractJobId(text: string): string | null {
  return text.match(JOB_ID_PATTERN)?.[0] ?? null;
}

export function textValue(value: unknown, fallback = "Not recorded"): string {
  if (value === null || value === undefined) return fallback;
  if (typeof value === "object") return fallback;
  const text = String(value).trim();
  return text || fallback;
}

export function findingSeverity(finding: RiskFinding): string {
  return textValue(finding.effective_severity ?? finding.severity, "unknown");
}

export function isProcessSummaryFinding(finding: RiskFinding): boolean {
  return finding.category === "process_risk_summary" || finding.rule_id === "PROCESS_RISK_SUMMARY";
}

export function riskSummaryLine(finding: RiskFinding): string {
  const extraData = finding.extra_data ?? {};
  const processName = textValue(extraData.process_name, "Unknown process");
  const pid = textValue(extraData.pid, "unknown PID");
  const confidence = textValue(extraData.detection_confidence, "triage indicator");
  return `${findingSeverity(finding).toUpperCase()}: ${processName} (PID ${pid}) - ${finding.title} (${confidence})`;
}

export function sortedFindingsByRisk(findings: RiskFinding[]): RiskFinding[] {
  return [...findings].sort((left, right) => {
    const severityOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
    return (severityOrder[findingSeverity(right).toLowerCase()] ?? 0) - (severityOrder[findingSeverity(left).toLowerCase()] ?? 0) || right.score - left.score;
  });
}

export async function loadChatbotJobContext(jobId: string): Promise<ChatbotJobContext> {
  const [
    job,
    reports,
    findings,
    iocs,
    pluginResults,
    processes,
    commands,
    networks,
    modules,
    memoryRegions,
    yaraMatches,
  ] = await Promise.all([
    getAnalysisJob(jobId),
    listReports({ job_id: jobId, limit: 10 }),
    listRiskFindings({ job_id: jobId, limit: 200 }),
    listIOCs({ job_id: jobId, limit: 200 }),
    listPluginResults(jobId, { limit: 100 }),
    listProcessArtifacts(jobId, { limit: 100 }),
    listCommandArtifacts(jobId, { limit: 50 }),
    listNetworkArtifacts(jobId, { limit: 50 }),
    listModuleArtifacts(jobId, { limit: 50 }),
    listMemoryRegionArtifacts(jobId, { limit: 50 }),
    listYaraMatches(jobId, { limit: 50 }),
  ]);

  return {
    job,
    reports: reports.items,
    findings: findings.items,
    iocs: iocs.items,
    pluginResults: pluginResults.items,
    processes: processes.items,
    commands: commands.items,
    networks: networks.items,
    modules: modules.items,
    memoryRegions: memoryRegions.items,
    yaraMatches: yaraMatches.items,
    totals: {
      findings: findings.total ?? findings.items.length,
      iocs: iocs.total ?? iocs.items.length,
    },
  };
}

export function summarizeJobContext(context: ChatbotJobContext): ChatbotJobSummary {
  const sortedFindings = sortedFindingsByRisk(context.findings);
  const processSummaries = sortedFindings.filter(isProcessSummaryFinding);
  const highPriority = sortedFindings.filter((finding) => ["critical", "high"].includes(findingSeverity(finding).toLowerCase()));
  const failedPlugins = context.pluginResults.filter((plugin) => plugin.status.toLowerCase() === "failed");
  const completedPlugins = context.pluginResults.filter((plugin) => plugin.status.toLowerCase() === "completed");
  const topFindings = (processSummaries.length > 0 ? processSummaries : sortedFindings).slice(0, 5);
  const topIocs = context.iocs.slice(0, 6).map((ioc) => `${ioc.ioc_type}: ${ioc.value}`);

  const lines = [
    `Summary for job ${context.job.id}`,
    `Status: ${context.job.status}. Profile: ${textValue(context.job.plugin_profile)}. OS: ${textValue(context.job.os_family)} ${textValue(context.job.os_version, "")}`.trim(),
    `Reports: ${context.reports.length}. Findings: ${context.totals.findings}. High/Critical: ${highPriority.length}. IOCs: ${context.totals.iocs}.`,
    `Plugins: ${completedPlugins.length}/${context.pluginResults.length} completed${failedPlugins.length > 0 ? `, ${failedPlugins.length} failed` : ""}.`,
    `Artifacts loaded for summary: ${context.processes.length} processes, ${context.commands.length} commands, ${context.networks.length} network rows, ${context.modules.length} modules, ${context.memoryRegions.length} memory regions, ${context.yaraMatches.length} YARA matches.`,
  ];

  if (topFindings.length > 0) {
    lines.push("", "Top triage points:");
    lines.push(...topFindings.map((finding) => `- ${riskSummaryLine(finding)}`));
  } else {
    lines.push("", "Top triage points: no risk findings were returned by the current APIs.");
  }

  if (topIocs.length > 0) {
    lines.push("", "Representative IOCs:");
    lines.push(...topIocs.map((ioc) => `- ${ioc}`));
  }

  if (failedPlugins.length > 0) {
    lines.push("", "Plugin issues:");
    lines.push(...failedPlugins.slice(0, 4).map((plugin) => `- ${plugin.plugin_name}: ${plugin.error_message || "failed without a recorded error message"}`));
  }

  lines.push("", "Analyst note: this is a fast standard-mode summary from stored RAMSight result APIs, not a final verdict.");

  return { answer: lines.join("\n"), jobId: context.job.id };
}

export async function summarizeJobForChatbot(jobId: string): Promise<ChatbotJobSummary> {
  return summarizeJobContext(await loadChatbotJobContext(jobId));
}
