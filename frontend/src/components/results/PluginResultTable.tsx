import { Badge } from "../ui/Badge";
import { Table } from "../ui/Table";
import type { PluginResult } from "../../types/domain";
import { displayValue, formatDateTime } from "../../utils/format";
import { statusTone } from "../../utils/status";

interface PluginResultTableProps {
  pluginResults: PluginResult[];
  limit?: number;
}

export function PluginResultTable({ pluginResults, limit = 100 }: PluginResultTableProps) {
  const visibleResults = pluginResults.slice(0, limit);

  return (
    <Table caption="Volatility plugin execution metadata">
      <thead>
        <tr>
          <th>Plugin</th>
          <th>Status</th>
          <th>Duration</th>
          <th>Parsed rows</th>
          <th>Error</th>
          <th>Raw output key</th>
          <th>Parsed output key</th>
        </tr>
      </thead>
      <tbody>
        {visibleResults.map((pluginResult) => (
          <tr key={pluginResult.id}>
            <td>
              {pluginResult.plugin_name}
              <span className="table-subtext">{pluginResult.source_plugin}</span>
            </td>
            <td><Badge tone={statusTone(pluginResult.status)}>{pluginResult.status}</Badge></td>
            <td>{pluginResult.duration_ms === null ? "Not recorded" : `${pluginResult.duration_ms} ms`}</td>
            <td>{pluginResult.parsed_record_count === null ? "Unknown" : pluginResult.parsed_record_count}</td>
            <td>{displayValue(pluginResult.error_message)}</td>
            <td><code>{displayValue(pluginResult.raw_output_key)}</code></td>
            <td>
              <code>{displayValue(pluginResult.parsed_output_key)}</code>
              <span className="table-subtext">Completed {formatDateTime(pluginResult.completed_at)}</span>
            </td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}
