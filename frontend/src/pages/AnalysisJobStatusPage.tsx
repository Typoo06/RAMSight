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
import { PluginResultTable } from "../components/results/PluginResultTable";
import { ReportSection } from "../components/results/ReportSection";
import { ResultSection } from "../components/results/ResultSection";
import { Badge } from "../components/ui/Badge";
import { Card } from "../components/ui/Card";
import { ErrorState } from "../components/ui/ErrorState";
import { LoadingState } from "../components/ui/LoadingState";
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
import { displayValue, formatDateTime } from "../utils/format";
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

function normalizedPluginProfile(profile: string | null | undefined): string | null {
  const normalized = (profile ?? "").trim().toLowerCase();
  if (!normalized || normalized === "not recorded") return null;
  return normalized;
}

function yaraStatusMessage(job: AnalysisJob, hasYaraResults: boolean): string {
  const pluginProfile = normalizedPluginProfile(job.plugin_profile);
  if (!pluginProfile) return "No YARA profile was recorded for this job.";
  if (pluginProfile === "windows_default") return "YARA was not selected for this analysis profile.";
  if (pluginProfile === "windows_memory_yara" && hasYaraResults) return "YARA-related results are available below.";
  if (pluginProfile === "windows_memory_yara") {
    return "YARA was requested, but exact skipped/no-match status is not available through the current results APIs.";
  }
  return "YARA status is not available for this analysis profile.";
}

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return value as Record<string, unknown>;
}

function numericPid(value: unknown): number | null {
  if (typeof value === "number" && Number.isInteger(value)) return value;
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!/^\d+$/.test(trimmed)) return null;
  return Number(trimmed);
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
  const [yaraMatches, setYaraMatches] = useState<YaraMatchArtifact[]>([]);

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
      listRiskFindings({ job_id: jobId, limit: 500 }),
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
  }, [jobId, job]);

  useEffect(() => {
    if (!jobId) return;
    let active = true;

    listRiskFindings({ job_id: jobId, limit: 500 })
      .then((response) => {
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
  }, [jobId]);

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
    () => sortedFindings.filter((finding) => severityRank(finding.severity) >= severityRank("high")),
    [sortedFindings],
  );
  const processRiskSummaries = useMemo(() => sortedFindings.filter(isProcessRiskSummary), [sortedFindings]);
  const networkFindings = useMemo(() => sortedFindings.filter(isNetworkFinding), [sortedFindings]);
  const moduleFindings = useMemo(() => sortedFindings.filter(isModuleOrPathFinding), [sortedFindings]);
  const memoryFindings = useMemo(() => sortedFindings.filter(isMemoryRegionFinding), [sortedFindings]);
  const yaraFindings = useMemo(() => sortedFindings.filter(isYaraFinding), [sortedFindings]);
  const networkIocs = useMemo(() => iocs.filter(isNetworkIOC), [iocs]);
  const moduleIocs = useMemo(() => iocs.filter(isModuleOrPathIOC), [iocs]);
  const memoryIocs = useMemo(() => iocs.filter(isMemoryRegionIOC), [iocs]);
  const yaraIocs = useMemo(() => iocs.filter(isYaraIOC), [iocs]);
  const yaraMessage = job ? yaraStatusMessage(job, yaraFindings.length > 0 || yaraIocs.length > 0) : "No YARA profile was recorded for this job.";
  const pidOptions = useMemo(
    () => collectPidOptions(findings, processArtifacts, commandArtifacts, networkArtifacts, moduleArtifacts, memoryRegions, yaraMatches),
    [commandArtifacts, findings, memoryRegions, moduleArtifacts, networkArtifacts, processArtifacts, yaraMatches],
  );
  const focusedArtifactCount = processArtifacts.length + commandArtifacts.length + networkArtifacts.length + moduleArtifacts.length + memoryRegions.length + yaraMatches.length;
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
            <div><dt>Status</dt><dd>{job.status}</dd></div>
            <div><dt>Duration</dt><dd>{job.duration_ms === null ? "Not recorded" : `${job.duration_ms} ms`}</dd></div>
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
            <div><dt>Plugin profile</dt><dd>{displayValue(job.plugin_profile)}</dd></div>
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
        <Card title="Findings"><p className="metric-value">{findings.length}</p><p className="muted">Total RAMSight findings</p></Card>
        <Card title="High priority"><p className="metric-value">{highPriorityFindings.length}</p><p className="muted">High or critical findings</p></Card>
        <Card title="Indicators"><p className="metric-value">{iocs.length}</p><p className="muted">Extracted IOC records</p></Card>
      </div>

      <ResultSection
        title="Top suspicious findings"
        loading={findingLoading}
        error={findingError}
        empty={sortedFindings.length === 0}
        emptyMessage={terminalResultEmptyMessage(job.status, "RAMSight completed this analysis with no risk findings recorded.")}
      >
        <FindingTable caption="Critical and high findings are shown first" findings={sortedFindings} limit={20} />
      </ResultSection>

      <ResultSection
        title="Process risk summary"
        loading={findingLoading}
        error={findingError}
        empty={processRiskSummaries.length === 0}
        emptyMessage={terminalResultEmptyMessage(job.status, "No process risk summary findings are available for this job.")}
      >
        <FindingTable caption="Process-level risk summaries" findings={processRiskSummaries} limit={20} />
      </ResultSection>

      <ResultSection
        title="Network indicators"
        loading={findingLoading || iocLoading}
        error={findingError || iocError}
        empty={networkFindings.length === 0 && networkIocs.length === 0}
        emptyMessage={terminalResultEmptyMessage(job.status, "No network findings or network IOC records are available for this job.")}
      >
        <div className="page-stack compact-stack">
          {networkFindings.length > 0 && <FindingTable caption="Network-related findings" findings={networkFindings} limit={20} />}
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
          {moduleFindings.length > 0 && <FindingTable caption="Module/path findings" findings={moduleFindings} limit={20} />}
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
          {memoryFindings.length > 0 && <FindingTable caption="Memory region findings" findings={memoryFindings} limit={20} />}
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
          {yaraFindings.length > 0 && <FindingTable caption="YARA-related findings" findings={yaraFindings} limit={20} />}
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
        <PluginResultTable pluginResults={pluginResults} />
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
        emptyMessage={terminalResultEmptyMessage(job.status, "No YARA matches were parsed for this job.")}
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
        title="IOC table"
        actions={iocExportActions}
        loading={iocLoading}
        error={iocError}
        empty={iocs.length === 0}
        emptyMessage={terminalResultEmptyMessage(job.status, "RAMSight completed this analysis with no IOC records extracted.")}
      >
        <div className="page-stack compact-stack">
          <IocTable caption="All IOC records for this analysis job" iocs={iocs} limit={100} />
          <p className="muted">IOC export downloads are served by RAMSight through the backend. If an export is not available yet, the download endpoint will return a clear error.</p>
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
