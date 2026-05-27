import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { getAnalysisJob, getAnalysisJobStatus } from "../api/analysisJobs";
import { listIOCs } from "../api/iocs";
import { listReports } from "../api/reports";
import { listRiskFindings } from "../api/riskFindings";
import { FindingTable } from "../components/results/FindingTable";
import { IocTable } from "../components/results/IocTable";
import { ReportSection } from "../components/results/ReportSection";
import { ResultSection } from "../components/results/ResultSection";
import { Badge } from "../components/ui/Badge";
import { Card } from "../components/ui/Card";
import { ErrorState } from "../components/ui/ErrorState";
import { LoadingState } from "../components/ui/LoadingState";
import type { AnalysisJob, IOC, Report, RiskFinding } from "../types/domain";
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

export function AnalysisJobStatusPage() {
  const { caseId, jobId } = useParams();
  const [error, setError] = useState<string | null>(null);
  const [findingError, setFindingError] = useState<string | null>(null);
  const [findingLoading, setFindingLoading] = useState(true);
  const [findings, setFindings] = useState<RiskFinding[]>([]);
  const [iocError, setIocError] = useState<string | null>(null);
  const [iocLoading, setIocLoading] = useState(true);
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [job, setJob] = useState<AnalysisJob | null>(null);
  const [loading, setLoading] = useState(true);
  const [reportError, setReportError] = useState<string | null>(null);
  const [reportLoading, setReportLoading] = useState(true);
  const [reports, setReports] = useState<Report[]>([]);

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
        title="IOC table"
        loading={iocLoading}
        error={iocError}
        empty={iocs.length === 0}
        emptyMessage={terminalResultEmptyMessage(job.status, "RAMSight completed this analysis with no IOC records extracted.")}
      >
        <IocTable caption="All IOC records for this analysis job" iocs={iocs} limit={100} />
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

      <Card title="Plugin and artifact references">
        <p className="muted">Plugin result rows, raw output references, parsed output references, and normalized artifact tables need dedicated backend query endpoints before RAMSight can render them here. No placeholder data is shown.</p>
      </Card>

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
