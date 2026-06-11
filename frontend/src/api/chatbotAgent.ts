import {
  extractJobId,
  findingSeverity,
  isProcessSummaryFinding,
  loadChatbotJobContext,
  riskSummaryLine,
  sortedFindingsByRisk,
  summarizeJobContext,
  textValue,
  type ChatbotJobContext,
} from "./chatbot";
import type { StoredChatMessage } from "./chatbotConversations";
import { generateLlmAnswer } from "./llm";
import { enrichWithGoogleAiMode } from "./webEnrichment";

export interface ChatbotAgentResponse {
  answer: string;
  jobId: string | null;
  mode: "Standard" | "DeepSeek LLM" | "Standard fallback";
}

interface Indicator {
  type: "ip" | "domain" | "url" | "hash" | "yara_rule" | "malware_family";
  value: string;
}

interface AgentDraft {
  answer: string;
  webEnrichment: string | null;
  webStatus: "enabled" | "unavailable" | "not_used";
}

const DOMAIN_REFUSAL = "I can only help with RAMSight job analysis, memory forensics, malware behavior, IOCs, and findings from the current job. Please ask a question related to the selected analysis job.";
const NEED_JOB = "Please provide a job_id or select a job conversation in the sidebar so I can answer from the correct RAMSight analysis job.";
const NOT_ENOUGH_EVIDENCE = "The current job data does not contain enough evidence to conclude that.";

function normalizeText(value: string): string {
  return value.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase();
}

function isOutOfScope(question: string): boolean {
  const normalized = normalizeText(question);
  if (/\b(travel|tour|laptop|toeic|cook|recipe|poem|personal)\b/.test(normalized)) return true;
  if (/du lich|mua laptop|nau an|viet tho|chuyen ca nhan/.test(normalized)) return true;
  return !/\b(ramsight|job|malware|memory|forensic|process|injection|yara|ioc|ip|domain|url|hash|finding|triage|report|persistence|privilege|investigate|indicator|reputation|threat intelligence|ma doc|nguy hiem|phan tich|bao cao|tom tat|chi bao)\b/.test(normalized);
}

function intentFor(question: string): string {
  const normalized = normalizeText(question);
  if (/summarize|summary|report|tom tat/.test(normalized)) return "summary";
  if (/malware|ma doc|nguy hiem|likely/.test(normalized)) return "malware";
  if (/high-risk|high risk|critical|process|powershell|tien trinh/.test(normalized)) return "high_risk_processes";
  if (/\bioc\b|indicator|ip|domain|url|hash|reputation|chi bao/.test(normalized)) return "iocs";
  if (/investigate|first|priority|triage|uu tien|dieu tra/.test(normalized)) return "investigate";
  if (/analyst note|note|ghi chu/.test(normalized)) return "analyst_notes";
  if (/yara/.test(normalized)) return "yara";
  return "fallback";
}

function extractIndicators(question: string): Indicator[] {
  const indicators: Indicator[] = [];
  const withoutUrls = question.replace(/\bhttps?:\/\/[^\s"'<>]+/gi, (value) => {
    indicators.push({ type: "url", value });
    return " ";
  });

  for (const match of withoutUrls.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)) indicators.push({ type: "ip", value: match[0] });
  for (const match of withoutUrls.matchAll(/\b[a-fA-F0-9]{32,64}\b/g)) indicators.push({ type: "hash", value: match[0] });
  for (const match of withoutUrls.matchAll(/\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g)) indicators.push({ type: "domain", value: match[0] });

  const yaraMatch = withoutUrls.match(/\byara\s+([A-Za-z0-9_.-]{4,120})/i);
  if (yaraMatch) indicators.push({ type: "yara_rule", value: yaraMatch[1] });
  const ruleLike = withoutUrls.match(/\b[A-Za-z]+_(?:Trojan|Backdoor|Malware|Ransom|Worm|Virus|Hacktool)_[A-Za-z0-9_.-]+\b/i);
  if (ruleLike) indicators.push({ type: "yara_rule", value: ruleLike[0] });
  const familyMatch = withoutUrls.match(/\b(?:family|malware)\s+([A-Za-z0-9_.-]{4,80})/i);
  if (familyMatch) indicators.push({ type: "malware_family", value: familyMatch[1] });

  const seen = new Set<string>();
  return indicators.filter((indicator) => {
    const key = `${indicator.type}:${indicator.value.toLowerCase()}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function topProcessFindings(context: ChatbotJobContext) {
  const sorted = sortedFindingsByRisk(context.findings);
  const processSummaries = sorted.filter(isProcessSummaryFinding);
  return (processSummaries.length > 0 ? processSummaries : sorted).slice(0, 6);
}

function highPriorityFindings(context: ChatbotJobContext) {
  return sortedFindingsByRisk(context.findings)
    .filter((finding) => ["critical", "high"].includes(findingSeverity(finding).toLowerCase()))
    .slice(0, 8);
}

function indicatorAppearsInJob(context: ChatbotJobContext, indicator: Indicator): boolean {
  const value = indicator.value.toLowerCase();
  if (indicator.type === "yara_rule") {
    return context.yaraMatches.some((match) => match.rule_name.toLowerCase() === value)
      || context.findings.some((finding) => String(finding.rule_name ?? "").toLowerCase() === value);
  }
  return context.iocs.some((ioc) => {
    const raw = ioc.value.toLowerCase();
    const normalized = String(ioc.normalized_value ?? "").toLowerCase();
    return raw === value || normalized === value;
  });
}

function shouldUseWebEnrichment(intent: string, question: string): boolean {
  if (!["iocs", "yara", "malware", "fallback"].includes(intent)) return false;
  if (/summarize|summary|analyst note|high-risk|high risk|show high-risk/i.test(question)) return false;
  return extractIndicators(question).length > 0 || /\breputation|threat intelligence\b/i.test(question);
}

function enrichmentQuery(indicator: Indicator): string {
  return `${indicator.type} ${indicator.value} threat intelligence malware reputation context`;
}

async function appendWebEnrichment(baseAnswer: string, context: ChatbotJobContext, question: string, intent: string): Promise<AgentDraft> {
  if (!shouldUseWebEnrichment(intent, question)) return { answer: baseAnswer, webEnrichment: null, webStatus: "not_used" };

  const indicator = extractIndicators(question)[0];
  if (!indicator) {
    return {
      answer: `${baseAnswer}\n\nWeb enrichment unavailable; answered from RAMSight job data only.`,
      webEnrichment: null,
      webStatus: "unavailable",
    };
  }

  const appears = indicatorAppearsInJob(context, indicator);
  const jobScopeLine = appears
    ? `Indicator ${indicator.value} appears in the current job data.`
    : `Indicator ${indicator.value} does not appear in the current job data.`;

  try {
    const enrichment = await enrichWithGoogleAiMode(enrichmentQuery(indicator));
    if (enrichment.enabled && enrichment.available && enrichment.content.trim()) {
      const webEnrichment = `Indicator: ${indicator.value}\n${enrichment.content.trim()}`;
      return {
        answer: [
        baseAnswer,
        "",
        jobScopeLine,
        "Web enrichment: enabled",
        `External web context (not a forensic verdict): ${enrichment.content.trim()}`,
        ].join("\n"),
        webEnrichment,
        webStatus: "enabled",
      };
    }
  } catch {
    // Optional provider failure must never break standard job-scoped answers.
  }

  return {
    answer: [
      baseAnswer,
      "",
      jobScopeLine,
      "Web enrichment unavailable; answered from RAMSight job data only.",
    ].join("\n"),
    webEnrichment: null,
    webStatus: "unavailable",
  };
}

function compactFinding(finding: ChatbotJobContext["findings"][number]) {
  const extraData = finding.extra_data ?? {};
  return {
    title: finding.title,
    severity: findingSeverity(finding),
    score: finding.score,
    category: finding.category,
    rule_id: finding.rule_id,
    rule_name: finding.rule_name,
    process_name: textValue(extraData.process_name, ""),
    pid: textValue(extraData.pid, ""),
    image_path: textValue(extraData.image_path, ""),
    command_line: textValue(extraData.command_line, ""),
    recommendation: finding.recommendation,
    description: finding.description,
  };
}

function buildLlmJobContext(context: ChatbotJobContext): Record<string, unknown> {
  const sorted = sortedFindingsByRisk(context.findings);
  const highCritical = sorted.filter((finding) => ["critical", "high"].includes(findingSeverity(finding).toLowerCase()));
  return {
    job_id: context.job.id,
    status: context.job.status,
    profile: context.job.plugin_profile,
    os: {
      family: context.job.os_family,
      version: context.job.os_version,
      architecture: context.job.architecture,
    },
    counts: {
      reports: context.reports.length,
      findings: context.totals.findings,
      high_critical_findings: highCritical.length,
      iocs: context.totals.iocs,
      yara_matches: context.yaraMatches.length,
      processes: context.processes.length,
    },
    top_high_critical_findings: highCritical.slice(0, 20).map(compactFinding),
    suspicious_processes: topProcessFindings(context).slice(0, 20).map(compactFinding),
    representative_iocs: context.iocs.slice(0, 20).map((ioc) => ({
      type: ioc.ioc_type,
      value: ioc.value,
      normalized_value: ioc.normalized_value,
      confidence: ioc.confidence,
      context: ioc.context,
    })),
    selected_yara_matches: context.yaraMatches.slice(0, 20).map((match) => ({
      rule_name: match.rule_name,
      target_type: match.target_type,
      target_identifier: match.target_identifier,
      source_plugin: match.source_plugin,
    })),
    selected_processes: context.processes.slice(0, 20).map((process) => ({
      pid: process.pid,
      ppid: process.ppid,
      name: process.name,
      image_path: process.image_path,
      command_line: process.command_line,
      user_name: process.user_name,
      is_hidden_candidate: process.is_hidden_candidate,
    })),
    selected_commands: context.commands.slice(0, 20).map((command) => ({
      pid: command.pid,
      process_name: command.process_name,
      command: command.command,
      shell_type: command.shell_type,
    })),
    selected_network_rows: context.networks.slice(0, 20).map((network) => ({
      pid: network.pid,
      process_name: network.process_name,
      protocol: network.protocol,
      local_address: network.local_address,
      local_port: network.local_port,
      remote_address: network.remote_address,
      remote_port: network.remote_port,
      state: network.state,
    })),
    selected_memory_regions: context.memoryRegions.slice(0, 20).map((region) => ({
      pid: region.pid,
      process_name: region.process_name,
      start_address: region.start_address,
      end_address: region.end_address,
      protection: region.protection,
      is_executable: region.is_executable,
      is_private: region.is_private,
      description: region.description,
    })),
  };
}

function answerMalwareAssessment(context: ChatbotJobContext): string {
  const highPriority = highPriorityFindings(context);
  const yaraRules = [...new Set(context.yaraMatches.map((match) => match.rule_name).filter(Boolean))].slice(0, 6);
  const topFindings = topProcessFindings(context).slice(0, 4);

  if (highPriority.length === 0 && topFindings.length === 0 && yaraRules.length === 0) {
    return `${NOT_ENOUGH_EVIDENCE}\n\nThis is a triage assessment, not a final forensic verdict.`;
  }

  const lines = [
    `Based on the current RAMSight findings for job ${context.job.id}, this job shows indicators consistent with malware activity.`,
    "Evidence includes:",
  ];
  if (highPriority.length > 0) lines.push(`- ${highPriority.length} high/critical finding(s).`);
  if (topFindings.length > 0) lines.push(...topFindings.map((finding) => `- ${riskSummaryLine(finding)}`));
  if (yaraRules.length > 0) lines.push(`- YARA matches: ${yaraRules.join(", ")}.`);
  lines.push("", "This is a triage assessment, not a final forensic verdict.");
  return lines.join("\n");
}

function answerHighRiskProcesses(context: ChatbotJobContext): string {
  const findings = highPriorityFindings(context);
  if (findings.length === 0) return `${NOT_ENOUGH_EVIDENCE}\n\nNo high/critical process findings are present in the loaded result APIs for job ${context.job.id}.`;
  return [`High-risk process findings for job ${context.job.id}:`, ...findings.map((finding) => `- ${riskSummaryLine(finding)}`)].join("\n");
}

function answerIocs(context: ChatbotJobContext): string {
  if (context.iocs.length === 0) return `${NOT_ENOUGH_EVIDENCE}\n\nNo IOC records are available through the current result APIs for job ${context.job.id}.`;
  const representative = context.iocs.slice(0, 10).map((ioc) => {
    const confidence = typeof ioc.confidence === "number" ? ` confidence ${ioc.confidence}` : "";
    return `- ${ioc.ioc_type}: ${ioc.value}${confidence}${ioc.context ? ` - ${ioc.context}` : ""}`;
  });
  return [
    `Representative suspicious IOCs for job ${context.job.id}:`,
    ...representative,
    "",
    "Prioritize IOCs linked to high/critical findings, suspicious process context, public network endpoints, or malware-specific YARA matches.",
  ].join("\n");
}

function answerInvestigateFirst(context: ChatbotJobContext): string {
  const findings = topProcessFindings(context).slice(0, 5);
  const failedPlugins = context.pluginResults.filter((plugin) => plugin.status.toLowerCase() === "failed").slice(0, 3);
  const lines = [`Recommended investigation order for job ${context.job.id}:`];
  if (findings.length > 0) {
    lines.push("1. Review the highest-risk process findings:");
    lines.push(...findings.map((finding) => `- ${riskSummaryLine(finding)}`));
  } else {
    lines.push(`1. ${NOT_ENOUGH_EVIDENCE}`);
  }
  if (context.iocs.length > 0) lines.push("2. Pivot on representative IOCs and check whether they map to high-risk processes.");
  if (context.yaraMatches.length > 0) lines.push("3. Review YARA matches and their target process or memory region context.");
  if (failedPlugins.length > 0) lines.push(`4. Check failed plugin coverage: ${failedPlugins.map((plugin) => plugin.plugin_name).join(", ")}.`);
  lines.push("Keep this as triage guidance until an analyst validates the evidence.");
  return lines.join("\n");
}

function answerAnalystNotes(context: ChatbotJobContext): string {
  const findings = topProcessFindings(context).slice(0, 4);
  const lines = [
    `Draft analyst notes for job ${context.job.id}:`,
    `- Job status: ${context.job.status}; profile: ${textValue(context.job.plugin_profile)}.`,
    `- RAMSight loaded ${context.totals.findings} finding(s), ${context.totals.iocs} IOC(s), and ${context.yaraMatches.length} YARA match row(s).`,
  ];
  if (findings.length > 0) lines.push(...findings.map((finding) => `- Triage point: ${riskSummaryLine(finding)}`));
  else lines.push(`- ${NOT_ENOUGH_EVIDENCE}`);
  lines.push("- Assessment remains triage-only pending analyst validation and supporting evidence review.");
  return lines.join("\n");
}

function answerYara(context: ChatbotJobContext): string {
  if (context.yaraMatches.length === 0) return `${NOT_ENOUGH_EVIDENCE}\n\nNo YARA match rows are available for job ${context.job.id}.`;
  const ruleCounts = new Map<string, number>();
  for (const match of context.yaraMatches) ruleCounts.set(match.rule_name, (ruleCounts.get(match.rule_name) ?? 0) + 1);
  const lines = [`YARA context for job ${context.job.id}:`];
  for (const [rule, count] of [...ruleCounts.entries()].slice(0, 8)) lines.push(`- ${rule}: ${count} match row(s)`);
  lines.push("A YARA match is a triage signal. Review the target process, memory region, and related findings before treating it as confirmed malware.");
  return lines.join("\n");
}

function answerFallback(context: ChatbotJobContext): string {
  const topFindings = topProcessFindings(context).slice(0, 3);
  if (topFindings.length === 0 && context.iocs.length === 0 && context.yaraMatches.length === 0) {
    return `${NOT_ENOUGH_EVIDENCE}\n\nAsk me to summarize the job, show high-risk processes, explain suspicious IOCs, or generate analyst notes.`;
  }
  return [
    `I can answer from job ${context.job.id}. The strongest available signals are:`,
    ...topFindings.map((finding) => `- ${riskSummaryLine(finding)}`),
    context.iocs.length > 0 ? `- ${context.iocs.length} IOC record(s) are available.` : "- No IOC records are available.",
    context.yaraMatches.length > 0 ? `- ${context.yaraMatches.length} YARA match row(s) are available.` : "- No YARA match rows are available.",
    "",
    "Please ask a more specific RAMSight question if you want a narrower explanation.",
  ].join("\n");
}

export async function answerChatbotQuestion(
  question: string,
  currentJobId: string | null,
  conversationMessages: StoredChatMessage[] = [],
): Promise<ChatbotAgentResponse> {
  const requestedJobId = extractJobId(question);
  const jobId = requestedJobId ?? currentJobId;

  if (isOutOfScope(question)) return { answer: DOMAIN_REFUSAL, jobId, mode: "Standard" };
  if (!jobId) return { answer: NEED_JOB, jobId: null, mode: "Standard" };

  // TODO: Future LLM mode should call a backend endpoint only when CHATBOT_MODE=llm and a server-side API key exists.
  const context = await loadChatbotJobContext(jobId);
  const intent = intentFor(question);

  let answer: string;
  if (intent === "summary") answer = summarizeJobContext(context).answer;
  else if (intent === "malware") answer = answerMalwareAssessment(context);
  else if (intent === "high_risk_processes") answer = answerHighRiskProcesses(context);
  else if (intent === "iocs") answer = answerIocs(context);
  else if (intent === "investigate") answer = answerInvestigateFirst(context);
  else if (intent === "analyst_notes") answer = answerAnalystNotes(context);
  else if (intent === "yara") answer = answerYara(context);
  else answer = answerFallback(context);

  const standardDraft = await appendWebEnrichment(answer, context, question, intent);

  try {
    const llm = await generateLlmAnswer({
      jobContext: buildLlmJobContext(context),
      conversationMessages: conversationMessages.slice(-8),
      userMessage: question,
      webEnrichment: standardDraft.webEnrichment,
      standardAnswer: standardDraft.answer,
      mode: "llm",
    });
    if (llm.success && llm.answer.trim()) {
      const webLine = standardDraft.webStatus === "enabled" ? "\n\nWeb enrichment: enabled" : "";
      return { answer: `Mode: DeepSeek LLM${webLine}\n\n${llm.answer.trim()}`, jobId: context.job.id, mode: "DeepSeek LLM" };
    }
    if (llm.enabled && llm.attempted) {
      return {
        answer: `Mode: Standard fallback\nLLM unavailable; answered with standard RAMSight agent.\n\n${standardDraft.answer}`,
        jobId: context.job.id,
        mode: "Standard fallback",
      };
    }
  } catch {
    return {
      answer: `Mode: Standard fallback\nLLM unavailable; answered with standard RAMSight agent.\n\n${standardDraft.answer}`,
      jobId: context.job.id,
      mode: "Standard fallback",
    };
  }

  return { answer: `Mode: Standard\n\n${standardDraft.answer}`, jobId: context.job.id, mode: "Standard" };
}
