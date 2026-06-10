import { Table } from "../ui/Table";
import type { IOC } from "../../types/domain";
import { displayValue } from "../../utils/format";

interface IocTableProps {
  caption: string;
  iocs: IOC[];
  limit?: number;
}

function confidenceLabel(value: number | null): string {
  if (value === null) return "Not recorded";
  return value.toFixed(2).replace(/\.00$/, "");
}

function copyToClipboard(value: string): void {
  if (!value || !navigator.clipboard) return;
  void navigator.clipboard.writeText(value);
}

function iocRole(ioc: IOC): string {
  const role = ioc.extra_data?.ioc_role;
  return typeof role === "string" && role.trim() ? role.replaceAll("_", " ") : "investigation artifact";
}

export function IocTable({ caption, iocs, limit = 50 }: IocTableProps) {
  const visibleIocs = iocs.slice(0, limit);
  const omittedCount = Math.max(iocs.length - visibleIocs.length, 0);

  return (
    <div className="table-block">
      <Table caption={caption}>
        <thead>
          <tr>
            <th>IOC type</th>
            <th>Role</th>
            <th>Indicator value</th>
            <th>Confidence</th>
            <th>Context</th>
            <th>Source plugin</th>
            <th>Linked finding</th>
          </tr>
        </thead>
        <tbody>
          {visibleIocs.map((ioc) => (
            <tr key={ioc.id}>
              <td>{ioc.ioc_type}</td>
              <td>{iocRole(ioc)}</td>
              <td className="long-text readable-code-cell">
                <code>{ioc.value}</code>
                <button className="copy-button" type="button" onClick={() => copyToClipboard(ioc.value)}>Copy</button>
              </td>
              <td>{confidenceLabel(ioc.confidence)}</td>
              <td className="long-text">{displayValue(ioc.context)}</td>
              <td className="long-text">{displayValue(ioc.source_plugin)}</td>
              <td className="long-text">{displayValue(ioc.risk_finding_id)}</td>
            </tr>
          ))}
        </tbody>
      </Table>
      {omittedCount > 0 && (
        <p className="table-note">Showing {visibleIocs.length} of {iocs.length} IOC records; {omittedCount} additional indicators are hidden for readability. Use the JSON/CSV export for the full set.</p>
      )}
    </div>
  );
}
