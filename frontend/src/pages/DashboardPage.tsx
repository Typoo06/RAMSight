import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { listAnalysisJobs } from "../api/analysisJobs";
import { listCases } from "../api/cases";
import { listEvidences } from "../api/evidences";
import { listIOCs } from "../api/iocs";
import { getReadiness, type ReadinessResponse } from "../api/readiness";
import { listReports } from "../api/reports";
import { listRiskFindings } from "../api/riskFindings";
import { Badge } from "../components/ui/Badge";
import { Card } from "../components/ui/Card";
import { LoadingState } from "../components/ui/LoadingState";
import { Table } from "../components/ui/Table";
import type { AnalysisJob, Case, Evidence, IOC, Report, RiskFinding } from "../types/domain";
import { displayValue, formatDateTime } from "../utils/format";
import { severityRank } from "../utils/results";
import { statusTone, type BadgeTone } from "../utils/status";

const CASE_LIMIT = 100;
const EVIDENCE_LIMIT = 100;
const JOB_LIMIT = 100;
const FINDING_LIMIT = 500;
const IOC_LIMIT = 500;
const REPORT_LIMIT = 100;

interface LoadedList<T> {
  error: string | null;
  items: T[];
  limit: number;
  loading: boolean;
}

function emptyList<T>(limit: number): LoadedList<T> {
  return { error: null, items: [], limit, loading: true };
}

function safeDashboardError(label: string): string {
  return `RAMSight could not load ${label}. Confirm the backend is running and CORS is configured for this frontend.`;
}

function listValue<T>({ error, items, limit, loading }: LoadedList<T>): string {
  if (loading) return "Loading";
  if (error) return "Unavailable";
  return items.length >= limit ? `${items.length}+` : String(items.length);
}

function isCapped<T>(list: LoadedList<T>): boolean {
  return !list.loading && !list.error && list.items.length >= list.limit;
}

function listNote<T>(label: string, list: LoadedList<T>): string {
  if (list.loading) return `Loading ${label}.`;
  if (list.error) return list.error;
  if (isCapped(list)) return `At least ${list.items.length} ${label} loaded; the dashboard is capped.`;
  return `${label} loaded from existing APIs.`;
}

function profileLabel(profile: string | null | undefined): string {
  if (profile === "windows_default") return "Standard Windows triage";
  if (profile === "windows_memory_yara") return "Elastic YARA (compatibility alias)";
  if (profile === "windows_memory_yara_elastic") return "Windows memory + Elastic YARA";
  if (profile === "windows_memory_yara_neo23x0") return "Windows memory + Neo23x0 YARA";
  if (profile === "windows_memory_yara_third_party_all") return "Third-party YARA All (slow)";
  if (profile === "windows_memory_deep") return "Deep Windows memory triage";
  if (profile === "windows_memory_deep_yara_elastic") return "Deep memory + Elastic YARA";
  if (profile === "windows_memory_deep_yara_neo23x0") return "Deep memory + Neo23x0 YARA";
  if (profile === "windows_memory_deep_yara_third_party_all") return "Deep memory + Third-party YARA All (very slow)";
  if (profile === "windows_malware_evasion") return "Windows malware evasion scan";
  if (profile === "windows_kernel_rootkit") return "Windows kernel/rootkit scan";
  if (profile === "windows_investigation_context") return "Windows investigation context scan";
  return displayValue(profile);
}

function readinessTone(value: string | null | undefined): BadgeTone {
  const normalized = (value ?? "").toLowerCase();
  if (["ready", "ok"].includes(normalized)) return "success";
  if (["not_ready", "error", "failed"].includes(normalized)) return "danger";
  if (["unknown", "unavailable"].includes(normalized)) return "warning";
  return "neutral";
}

function sortJobs(jobs: AnalysisJob[]): AnalysisJob[] {
  return [...jobs].sort((left, right) => {
    const leftTime = Date.parse(left.completed_at ?? left.updated_at ?? left.created_at);
    const rightTime = Date.parse(right.completed_at ?? right.updated_at ?? right.created_at);
    return rightTime - leftTime;
  });
}

function countByJob<T extends { analysis_job_id: string }>(items: T[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const item of items) counts.set(item.analysis_job_id, (counts.get(item.analysis_job_id) ?? 0) + 1);
  return counts;
}

function SummaryCard({ note, title, value }: { note: string; title: string; value: string }) {
  return (
    <Card title={title}>
      <p className="metric-value metric-value-text">{value}</p>
      <p className="muted">{note}</p>
    </Card>
  );
}

export function DashboardPage() {
  const [cases, setCases] = useState<LoadedList<Case>>(emptyList(CASE_LIMIT));
  const [evidences, setEvidences] = useState<LoadedList<Evidence>>(emptyList(EVIDENCE_LIMIT));
  const [jobs, setJobs] = useState<LoadedList<AnalysisJob>>(emptyList(JOB_LIMIT));
  const [findings, setFindings] = useState<LoadedList<RiskFinding>>(emptyList(FINDING_LIMIT));
  const [iocs, setIocs] = useState<LoadedList<IOC>>(emptyList(IOC_LIMIT));
  const [reports, setReports] = useState<LoadedList<Report>>(emptyList(REPORT_LIMIT));
  const [readiness, setReadiness] = useState<ReadinessResponse | null>(null);
  const [readinessError, setReadinessError] = useState<string | null>(null);
  const [readinessLoading, setReadinessLoading] = useState(true);

  useEffect(() => {
    let active = true;
    const load = async () => {
      setReadinessLoading(true);
      setCases(emptyList(CASE_LIMIT));
      setEvidences(emptyList(EVIDENCE_LIMIT));
      setJobs(emptyList(JOB_LIMIT));
      setFindings(emptyList(FINDING_LIMIT));
      setIocs(emptyList(IOC_LIMIT));
      setReports(emptyList(REPORT_LIMIT));

      const [readyResult, caseResult, evidenceResult, jobResult, findingResult, iocResult, reportResult] = await Promise.allSettled([
        getReadiness(),
        listCases({ limit: CASE_LIMIT }),
        listEvidences({ limit: EVIDENCE_LIMIT }),
        listAnalysisJobs({ limit: JOB_LIMIT }),
        listRiskFindings({ limit: FINDING_LIMIT }),
        listIOCs({ limit: IOC_LIMIT }),
        listReports({ limit: REPORT_LIMIT }),
      ]);

      if (!active) return;

      if (readyResult.status === "fulfilled") {
        setReadiness(readyResult.value);
        setReadinessError(null);
      } else {
        setReadiness(null);
        setReadinessError("RAMSight readiness is unavailable. Confirm the backend is running and reachable from this frontend.");
      }
      setReadinessLoading(false);

      setCases(caseResult.status === "fulfilled"
        ? { error: null, items: caseResult.value.items, limit: CASE_LIMIT, loading: false }
        : { error: safeDashboardError("cases"), items: [], limit: CASE_LIMIT, loading: false });
      setEvidences(evidenceResult.status === "fulfilled"
        ? { error: null, items: evidenceResult.value.items, limit: EVIDENCE_LIMIT, loading: false }
        : { error: safeDashboardError("evidence metadata"), items: [], limit: EVIDENCE_LIMIT, loading: false });
      setJobs(jobResult.status === "fulfilled"
        ? { error: null, items: jobResult.value.items, limit: JOB_LIMIT, loading: false }
        : { error: safeDashboardError("analysis jobs"), items: [], limit: JOB_LIMIT, loading: false });
      setFindings(findingResult.status === "fulfilled"
        ? { error: null, items: findingResult.value.items, limit: FINDING_LIMIT, loading: false }
        : { error: safeDashboardError("risk findings"), items: [], limit: FINDING_LIMIT, loading: false });
      setIocs(iocResult.status === "fulfilled"
        ? { error: null, items: iocResult.value.items, limit: IOC_LIMIT, loading: false }
        : { error: safeDashboardError("IOC records"), items: [], limit: IOC_LIMIT, loading: false });
      setReports(reportResult.status === "fulfilled"
        ? { error: null, items: reportResult.value.items, limit: REPORT_LIMIT, loading: false }
        : { error: safeDashboardError("report metadata"), items: [], limit: REPORT_LIMIT, loading: false });
    };

    void load();
    return () => {
      active = false;
    };
  }, []);

  const evidenceNameById = useMemo(() => new Map(evidences.items.map((evidence) => [evidence.id, evidence.original_filename])), [evidences.items]);
  const findingCountByJob = useMemo(() => countByJob(findings.items), [findings.items]);
  const iocCountByJob = useMemo(() => countByJob(iocs.items), [iocs.items]);
  const recentJobs = useMemo(() => sortJobs(jobs.items).slice(0, 5), [jobs.items]);
  const highCriticalFindings = useMemo(
    () => findings.items.filter((finding) => severityRank(finding.effective_severity ?? finding.severity) >= severityRank("high")),
    [findings.items],
  );
  const unreviewedFindings = useMemo(
    () => findings.items.filter((finding) => !finding.review_status || finding.review_status === "new"),
    [findings.items],
  );
  const failedJobs = useMemo(() => jobs.items.filter((job) => job.status.toLowerCase() === "failed"), [jobs.items]);
  const latestCompletedJob = useMemo(() => recentJobs.find((job) => job.status.toLowerCase() === "completed") ?? null, [recentJobs]);
  const highCriticalValue = findings.error ? "Unavailable" : `${highCriticalFindings.length}${isCapped(findings) ? "+" : ""}`;
  const highCriticalNote = findings.error
    ?? (isCapped(findings)
      ? "At least this many high or critical triage findings are present in loaded records."
      : "Loaded high or critical triage findings.");

  return (
    <div className="page-stack">
      <section className="page-heading">
        <span className="eyebrow">Dashboard</span>
        <h2>RAMSight operational overview</h2>
        <p>Monitor the local triage workspace, review loaded analysis records, and confirm readiness before a demo or thesis walkthrough.</p>
      </section>

      <div className="dashboard-grid">
        <SummaryCard title="Loaded cases" value={listValue(cases)} note={listNote("case records", cases)} />
        <SummaryCard title="Loaded evidence" value={listValue(evidences)} note={listNote("evidence records", evidences)} />
        <SummaryCard title="Loaded jobs" value={listValue(jobs)} note={listNote("analysis jobs", jobs)} />
        <SummaryCard title="High / critical loaded findings" value={highCriticalValue} note={highCriticalNote} />
        <SummaryCard title="Loaded IOCs" value={listValue(iocs)} note={listNote("IOC records", iocs)} />
        <SummaryCard title="Loaded reports" value={listValue(reports)} note={listNote("HTML report metadata rows", reports)} />
      </div>

      <div className="detail-grid">
        <Card title="Local readiness">
          {readinessLoading && <LoadingState label="Checking RAMSight readiness..." />}
          {!readinessLoading && readinessError && <p className="error-text">{readinessError}</p>}
          {!readinessLoading && readiness && (
            <div className="readiness-panel">
              <div className="readiness-row">
                <span>Overall</span>
                <Badge tone={readinessTone(readiness.status)}>{readiness.status}</Badge>
              </div>
              {(["database", "redis", "object_storage"] as const).map((name) => (
                <div className="readiness-row" key={name}>
                  <span>{name.replace("_", " ")}</span>
                  <Badge tone={readinessTone(readiness.checks[name])}>{readiness.checks[name] ?? "unknown"}</Badge>
                </div>
              ))}
            </div>
          )}
          <p className="section-note">Readiness shows safe dependency names only. It does not expose credentials, storage keys, or local paths.</p>
        </Card>

        <Card title="Attention queue">
          <dl className="metadata-list metadata-list-single dashboard-attention-list">
            <div><dt>High / critical loaded findings</dt><dd>{findings.error ? "Unavailable" : highCriticalFindings.length}</dd></div>
            <div><dt>Unreviewed loaded findings</dt><dd>{findings.error ? "Unavailable" : unreviewedFindings.length}</dd></div>
            <div><dt>Failed loaded jobs</dt><dd>{jobs.error ? "Unavailable" : failedJobs.length}</dd></div>
          </dl>
          <p className="section-note">Counts are based on loaded dashboard records and may be capped. Plugin failure details are shown on individual result pages.</p>
        </Card>
      </div>

      <Card title="Recent analysis jobs" actions={<Link className="text-link" to="/cases">View cases</Link>}>
        {jobs.loading && <LoadingState label="Loading recent RAMSight analysis jobs..." />}
        {!jobs.loading && jobs.error && <p className="error-text">{jobs.error}</p>}
        {!jobs.loading && !jobs.error && recentJobs.length === 0 && (
          <p className="muted">No analysis jobs are available yet. Open or create a case, upload evidence, and start a RAMSight analysis job.</p>
        )}
        {!jobs.loading && !jobs.error && recentJobs.length > 0 && (
          <Table caption="Most recently updated analysis jobs loaded by the dashboard">
            <thead>
              <tr>
                <th>Status</th>
                <th>Evidence</th>
                <th>Profile</th>
                <th>Findings loaded</th>
                <th>IOCs loaded</th>
                <th>Updated / completed</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {recentJobs.map((job) => (
                <tr key={job.id}>
                  <td><Badge tone={statusTone(job.status)}>{job.status}</Badge></td>
                  <td className="long-text">{evidences.error ? displayValue(job.evidence_id) : displayValue(evidenceNameById.get(job.evidence_id))}</td>
                  <td>{profileLabel(job.plugin_profile)}</td>
                  <td>{findings.error ? "Unavailable" : (findingCountByJob.get(job.id) ?? 0)}</td>
                  <td>{iocs.error ? "Unavailable" : (iocCountByJob.get(job.id) ?? 0)}</td>
                  <td>
                    {formatDateTime(job.completed_at ?? job.updated_at)}
                    <span className="table-subtext">Updated: {formatDateTime(job.updated_at)}</span>
                  </td>
                  <td>
                    <Link className="text-link" to={`/cases/${job.case_id}/jobs/${job.id}`}>Open result</Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>

      <Card title="Quick actions">
        <div className="button-row">
          <Link className="button button-secondary button-small" to="/cases">View cases</Link>
          <Link className="button button-secondary button-small" to="/cases/new">Create case</Link>
          {latestCompletedJob && (
            <Link className="button button-secondary button-small" to={`/cases/${latestCompletedJob.case_id}/jobs/${latestCompletedJob.id}`}>
              Open latest completed analysis
            </Link>
          )}
        </div>
        <p className="section-note">Use cases to upload evidence, start analysis jobs, and review triage indicators that support investigation. For local setup checks, see the operations runbook.</p>
      </Card>
    </div>
  );
}
