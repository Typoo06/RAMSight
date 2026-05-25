import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { createAnalysisJob, listAnalysisJobs } from "../api/analysisJobs";
import { getCase } from "../api/cases";
import { listEvidences } from "../api/evidences";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { ErrorState } from "../components/ui/ErrorState";
import { LoadingState } from "../components/ui/LoadingState";
import { Table } from "../components/ui/Table";
import type { AnalysisJob, Case, Evidence } from "../types/domain";
import { displayValue, formatBytes, formatDateTime, shortHash } from "../utils/format";
import { statusTone } from "../utils/status";

function evidenceOsFamily(evidence: Evidence): string {
  return evidence.os_family || "windows";
}

export function CaseDetailPage() {
  const { caseId } = useParams();
  const navigate = useNavigate();
  const [caseRecord, setCaseRecord] = useState<Case | null>(null);
  const [caseError, setCaseError] = useState<string | null>(null);
  const [caseLoading, setCaseLoading] = useState(true);
  const [evidenceError, setEvidenceError] = useState<string | null>(null);
  const [evidenceLoading, setEvidenceLoading] = useState(true);
  const [evidences, setEvidences] = useState<Evidence[]>([]);
  const [jobs, setJobs] = useState<AnalysisJob[]>([]);
  const [jobsError, setJobsError] = useState<string | null>(null);
  const [jobsLoading, setJobsLoading] = useState(true);
  const [startError, setStartError] = useState<string | null>(null);
  const [startingEvidenceId, setStartingEvidenceId] = useState<string | null>(null);

  useEffect(() => {
    if (!caseId) return;
    let active = true;

    getCase(caseId)
      .then((item) => {
        if (active) setCaseRecord(item);
      })
      .catch((err: unknown) => {
        if (active) setCaseError(err instanceof Error ? err.message : "RAMSight could not load this case.");
      })
      .finally(() => {
        if (active) setCaseLoading(false);
      });

    listEvidences({ case_id: caseId, limit: 100 })
      .then((response) => {
        if (active) setEvidences(response.items);
      })
      .catch((err: unknown) => {
        if (active) setEvidenceError(err instanceof Error ? err.message : "RAMSight could not load evidence metadata.");
      })
      .finally(() => {
        if (active) setEvidenceLoading(false);
      });

    listAnalysisJobs({ case_id: caseId, limit: 100 })
      .then((response) => {
        if (active) setJobs(response.items);
      })
      .catch((err: unknown) => {
        if (active) setJobsError(err instanceof Error ? err.message : "RAMSight could not load analysis jobs.");
      })
      .finally(() => {
        if (active) setJobsLoading(false);
      });

    return () => {
      active = false;
    };
  }, [caseId]);

  const evidenceNameById = useMemo(() => {
    return new Map(evidences.map((evidence) => [evidence.id, evidence.original_filename]));
  }, [evidences]);

  async function handleStartAnalysis(evidence: Evidence) {
    if (!caseId) return;
    setStartError(null);
    setStartingEvidenceId(evidence.id);
    try {
      const job = await createAnalysisJob({
        case_id: caseId,
        evidence_id: evidence.id,
        os_family: evidenceOsFamily(evidence),
        os_version: evidence.os_version,
        architecture: evidence.architecture,
        kernel_version: evidence.kernel_version,
        symbol_table: evidence.symbol_table,
      });
      navigate(`/cases/${caseId}/jobs/${job.id}`);
    } catch (err) {
      setStartError(err instanceof Error ? err.message : "RAMSight could not create an analysis job.");
    } finally {
      setStartingEvidenceId(null);
    }
  }

  if (!caseId) return <ErrorState message="RAMSight could not identify the requested case." />;
  if (caseLoading) return <LoadingState label="Loading RAMSight case..." />;
  if (caseError) return <ErrorState message={caseError} />;
  if (!caseRecord) return <ErrorState message="RAMSight did not return case metadata." />;

  return (
    <div className="page-stack">
      <section className="page-heading page-heading-row">
        <div>
          <span className="eyebrow">Case detail</span>
          <h2>{caseRecord.name}</h2>
          <p>{caseRecord.case_code}</p>
        </div>
        <Badge tone={statusTone(caseRecord.status)}>{caseRecord.status}</Badge>
      </section>

      <div className="detail-grid">
        <Card title="Case metadata">
          <dl className="metadata-list">
            <div><dt>Case code</dt><dd>{caseRecord.case_code}</dd></div>
            <div><dt>Status</dt><dd>{caseRecord.status}</dd></div>
            <div><dt>Created</dt><dd>{formatDateTime(caseRecord.created_at)}</dd></div>
            <div><dt>Updated</dt><dd>{formatDateTime(caseRecord.updated_at)}</dd></div>
          </dl>
          <p>{caseRecord.description || "No case description has been recorded."}</p>
        </Card>
        <Card title="Workflow" actions={<Link className="text-link" to="/cases">Back to cases</Link>}>
          <p>Upload memory evidence, start a queued worker analysis, then monitor the job until RAMSight reaches a terminal status.</p>
          <Link className="text-link" to={`/cases/${caseId}/evidence/upload`}>
            Upload evidence
          </Link>
        </Card>
      </div>

      {startError && <ErrorState message={startError} title="Analysis job could not be created" />}

      <Card title="Evidence" actions={<Link className="text-link" to={`/cases/${caseId}/evidence/upload`}>Upload evidence</Link>}>
        {evidenceLoading && <LoadingState label="Loading RAMSight evidence metadata..." />}
        {evidenceError && <ErrorState message={evidenceError} title="Evidence metadata unavailable" />}
        {!evidenceLoading && !evidenceError && evidences.length === 0 && (
          <p className="muted">No evidence has been uploaded for this case yet.</p>
        )}
        {!evidenceLoading && !evidenceError && evidences.length > 0 && (
          <div className="item-list">
            {evidences.map((evidence) => (
              <article className="item-panel" key={evidence.id}>
                <header className="item-panel-header">
                  <div>
                    <strong>{evidence.original_filename}</strong>
                    <span>{displayValue(evidence.source_type)} evidence</span>
                  </div>
                  <Button
                    disabled={startingEvidenceId === evidence.id}
                    type="button"
                    onClick={() => void handleStartAnalysis(evidence)}
                  >
                    {startingEvidenceId === evidence.id ? "Starting..." : "Start analysis"}
                  </Button>
                </header>
                <dl className="metadata-list metadata-list-wide">
                  <div><dt>OS family</dt><dd>{displayValue(evidence.os_family)}</dd></div>
                  <div><dt>OS version</dt><dd>{displayValue(evidence.os_version)}</dd></div>
                  <div><dt>Architecture</dt><dd>{displayValue(evidence.architecture)}</dd></div>
                  <div><dt>Kernel version</dt><dd>{displayValue(evidence.kernel_version)}</dd></div>
                  <div><dt>Symbol table</dt><dd>{displayValue(evidence.symbol_table)}</dd></div>
                  <div><dt>Acquisition tool</dt><dd>{displayValue(evidence.acquisition_tool)}</dd></div>
                  <div><dt>Acquisition time</dt><dd>{formatDateTime(evidence.acquisition_time)}</dd></div>
                  <div><dt>Size</dt><dd>{formatBytes(evidence.size_bytes)}</dd></div>
                  <div><dt>MD5</dt><dd><code title={evidence.md5 ?? undefined}>{shortHash(evidence.md5)}</code></dd></div>
                  <div><dt>SHA256</dt><dd><code title={evidence.sha256 ?? undefined}>{shortHash(evidence.sha256)}</code></dd></div>
                </dl>
              </article>
            ))}
          </div>
        )}
      </Card>

      <Card title="Analysis jobs">
        {jobsLoading && <LoadingState label="Loading RAMSight analysis jobs..." />}
        {jobsError && <ErrorState message={jobsError} title="Analysis jobs unavailable" />}
        {!jobsLoading && !jobsError && jobs.length === 0 && (
          <p className="muted">No analysis jobs have been created for this case yet.</p>
        )}
        {!jobsLoading && !jobsError && jobs.length > 0 && (
          <Table caption="RAMSight analysis jobs for this case">
            <thead>
              <tr>
                <th>Status</th>
                <th>Evidence</th>
                <th>OS</th>
                <th>Updated</th>
                <th>Duration</th>
                <th>Monitor</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((job) => (
                <tr key={job.id}>
                  <td><Badge tone={statusTone(job.status)}>{job.status}</Badge></td>
                  <td>{evidenceNameById.get(job.evidence_id) ?? job.evidence_id}</td>
                  <td>{displayValue(job.os_family)}</td>
                  <td>{formatDateTime(job.updated_at)}</td>
                  <td>{job.duration_ms === null ? "Not recorded" : `${job.duration_ms} ms`}</td>
                  <td>
                    <Link className="text-link" to={`/cases/${caseId}/jobs/${job.id}`}>
                      View status
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </div>
  );
}
