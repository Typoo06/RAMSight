import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { getAnalysisJob, getAnalysisJobStatus } from "../api/analysisJobs";
import { Badge } from "../components/ui/Badge";
import { Card } from "../components/ui/Card";
import { ErrorState } from "../components/ui/ErrorState";
import { LoadingState } from "../components/ui/LoadingState";
import type { AnalysisJob } from "../types/domain";
import { displayValue, formatDateTime } from "../utils/format";
import { isActiveJobStatus, statusTone } from "../utils/status";

export function AnalysisJobStatusPage() {
  const { caseId, jobId } = useParams();
  const [error, setError] = useState<string | null>(null);
  const [job, setJob] = useState<AnalysisJob | null>(null);
  const [loading, setLoading] = useState(true);

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

  if (!caseId || !jobId) return <ErrorState message="RAMSight could not identify the requested analysis job." />;
  if (loading) return <LoadingState label="Loading RAMSight analysis job..." />;
  if (error && !job) return <ErrorState message={error} />;
  if (!job) return <ErrorState message="RAMSight did not return analysis job metadata." />;

  return (
    <div className="page-stack">
      <section className="page-heading page-heading-row">
        <div>
          <span className="eyebrow">Analysis status</span>
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

