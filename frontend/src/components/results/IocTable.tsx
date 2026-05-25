import { Table } from "../ui/Table";
import type { IOC } from "../../types/domain";
import { displayValue } from "../../utils/format";

interface IocTableProps {
  caption: string;
  iocs: IOC[];
  limit?: number;
}

export function IocTable({ caption, iocs, limit = 50 }: IocTableProps) {
  const visibleIocs = iocs.slice(0, limit);

  return (
    <Table caption={caption}>
      <thead>
        <tr>
          <th>Type</th>
          <th>Value</th>
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
            <td><code>{ioc.value}</code></td>
            <td>{ioc.confidence === null ? "Not recorded" : ioc.confidence}</td>
            <td>{displayValue(ioc.context)}</td>
            <td>{displayValue(ioc.source_plugin)}</td>
            <td>{displayValue(ioc.risk_finding_id)}</td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

