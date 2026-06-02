import { Badge } from "../ui/Badge";
import { Table } from "../ui/Table";
import { reportDownloadUrl } from "../../api/reports";
import type { Report } from "../../types/domain";
import { displayValue, formatDateTime } from "../../utils/format";
import { statusTone } from "../../utils/status";

interface ReportSectionProps {
  reports: Report[];
}

export function ReportSection({ reports }: ReportSectionProps) {
  return (
    <div className="page-stack compact-stack">
      <Table caption="RAMSight report metadata">
        <thead>
          <tr>
            <th>Type</th>
            <th>Format</th>
            <th>OS</th>
            <th>Generated</th>
            <th>Bucket</th>
            <th>Object key</th>
            <th>Download</th>
          </tr>
        </thead>
        <tbody>
          {reports.map((report) => (
            <tr key={report.id}>
              <td>{report.report_type}</td>
              <td><Badge tone={statusTone(report.format)}>{report.format}</Badge></td>
              <td>{displayValue(report.os_family)}</td>
              <td>{formatDateTime(report.generated_at)}</td>
              <td>{displayValue(report.storage_bucket)}</td>
              <td><code>{displayValue(report.storage_key)}</code></td>
              <td>
                <a className="button button-secondary button-small" href={reportDownloadUrl(report.id)}>
                  Download HTML report
                </a>
              </td>
            </tr>
          ))}
        </tbody>
      </Table>
      <p className="muted">RAMSight downloads generated HTML reports through the backend so MinIO credentials stay private. Metadata remains visible for analyst traceability.</p>
    </div>
  );
}
