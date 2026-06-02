import { Badge } from "../ui/Badge";
import { Table } from "../ui/Table";
import type { RiskFinding } from "../../types/domain";
import { displayValue } from "../../utils/format";
import { findingEvidenceContext } from "../../utils/results";
import { statusTone } from "../../utils/status";

interface FindingTableProps {
  caption: string;
  findings: RiskFinding[];
  limit?: number;
}

export function FindingTable({ caption, findings, limit = 20 }: FindingTableProps) {
  const visibleFindings = findings.slice(0, limit);

  return (
    <Table caption={caption}>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Finding</th>
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
            <tr key={finding.id}>
              <td><Badge tone={statusTone(finding.severity)}>{finding.severity}</Badge></td>
              <td>
                <strong>{finding.rule_name || finding.title}</strong>
                {finding.rule_name && <span className="table-subtext">{finding.title}</span>}
                {evidenceContext.length > 0 && <span className="table-subtext table-context">{evidenceContext.join(" | ")}</span>}
              </td>
              <td>{displayValue(finding.category)}</td>
              <td>{displayValue(finding.artifact_type)}</td>
              <td>{displayValue(finding.source_plugin)}</td>
              <td>{finding.score}</td>
              <td>{displayValue(finding.recommendation)}</td>
            </tr>
          );
        })}
      </tbody>
    </Table>
  );
}
