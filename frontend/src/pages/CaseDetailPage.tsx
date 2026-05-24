import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { getCase } from "../api/cases";
import { Badge } from "../components/ui/Badge";
import { Card } from "../components/ui/Card";
import { ErrorState } from "../components/ui/ErrorState";
import { LoadingState } from "../components/ui/LoadingState";
import type { Case } from "../types/domain";
import { statusTone } from "../utils/status";

export function CaseDetailPage() {
  const { caseId } = useParams();
  const [caseRecord, setCaseRecord] = useState<Case | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!caseId) return;
    let active = true;
    getCase(caseId)
      .then((item) => {
        if (active) setCaseRecord(item);
      })
      .catch((err: unknown) => {
        if (active) setError(err instanceof Error ? err.message : "RAMSight could not load this case.");
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [caseId]);

  if (!caseId) return <ErrorState message="RAMSight could not identify the requested case." />;
  if (loading) return <LoadingState label="Loading RAMSight case..." />;
  if (error) return <ErrorState message={error} />;
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
            <div><dt>Created</dt><dd>{new Date(caseRecord.created_at).toLocaleString()}</dd></div>
            <div><dt>Updated</dt><dd>{new Date(caseRecord.updated_at).toLocaleString()}</dd></div>
          </dl>
          <p>{caseRecord.description || "No case description has been recorded."}</p>
        </Card>
        <Card title="Next workflow steps">
          <p>Evidence upload, analysis jobs, and analysis result tables are intentionally reserved for upcoming RAMSight tasks.</p>
          <Link className="text-link" to="/cases">
            Back to cases
          </Link>
        </Card>
      </div>

      <Card title="Evidence placeholder">
        <p className="muted">Evidence intake will appear here in Task 12B.</p>
      </Card>
      <Card title="Analysis placeholder">
        <p className="muted">Analysis status and result navigation will appear here in later frontend tasks.</p>
      </Card>
    </div>
  );
}
