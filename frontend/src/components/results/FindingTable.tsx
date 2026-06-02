import { Fragment, useState } from "react";
import { Badge } from "../ui/Badge";
import { Table } from "../ui/Table";
import type { RiskFinding } from "../../types/domain";
import { displayValue } from "../../utils/format";
import { findingEvidenceContext } from "../../utils/results";
import { statusTone } from "../../utils/status";
import { FindingReviewPanel } from "./FindingReviewPanel";

interface FindingTableProps {
  caption: string;
  findings: RiskFinding[];
  limit?: number;
  onFindingUpdated?: (finding: RiskFinding) => void;
}

function reviewStatus(finding: RiskFinding): string {
  return finding.review_status || "new";
}

function effectiveSeverity(finding: RiskFinding): string {
  return finding.effective_severity || finding.severity;
}

export function FindingTable({ caption, findings, limit = 20, onFindingUpdated }: FindingTableProps) {
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const visibleFindings = findings.slice(0, limit);

  return (
    <Table caption={caption}>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Finding</th>
          <th>Review</th>
          <th>Category</th>
          <th>Artifact</th>
          <th>Source plugin</th>
          <th>Score</th>
          <th>Recommendation</th>
        </tr>
      </thead>
      <tbody>
        {visibleFindings.map((finding) => {
          const evidenceContext = findingEvidenceContext(finding);

          return (
            <Fragment key={finding.id}>
              <tr>
                <td>
                  <Badge tone={statusTone(effectiveSeverity(finding))}>{effectiveSeverity(finding)}</Badge>
                  {finding.severity_override && <span className="table-subtext">Detected: {finding.severity}</span>}
                </td>
                <td>
                  <strong>{finding.rule_name || finding.title}</strong>
                  {finding.rule_name && <span className="table-subtext">{finding.title}</span>}
                  {evidenceContext.length > 0 && <span className="table-subtext table-context">{evidenceContext.join(" | ")}</span>}
                </td>
                <td>
                  <Badge tone={statusTone(reviewStatus(finding))}>{reviewStatus(finding)}</Badge>
                  {finding.analyst_verdict && <span className="table-subtext">Verdict: {finding.analyst_verdict.replaceAll("_", " ")}</span>}
                  {finding.reviewed_by_name && <span className="table-subtext">By: {finding.reviewed_by_name}</span>}
                  <button
                    className="button button-subtle button-small review-toggle"
                    type="button"
                    onClick={() => setExpandedFindingId((current) => (current === finding.id ? null : finding.id))}
                  >
                    {expandedFindingId === finding.id ? "Close" : "Review"}
                  </button>
                </td>
                <td>{displayValue(finding.category)}</td>
                <td>{displayValue(finding.artifact_type)}</td>
                <td>{displayValue(finding.source_plugin)}</td>
                <td>{finding.score}</td>
                <td>{displayValue(finding.recommendation)}</td>
              </tr>
              {expandedFindingId === finding.id && (
                <tr>
                  <td colSpan={8}>
                    <FindingReviewPanel finding={finding} onSaved={(updated) => onFindingUpdated?.(updated)} />
                  </td>
                </tr>
              )}
            </Fragment>
          );
        })}
      </tbody>
    </Table>
  );
}
