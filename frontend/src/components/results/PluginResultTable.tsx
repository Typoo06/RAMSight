import { Badge } from "../ui/Badge";
import { Table } from "../ui/Table";
import { pluginRawOutputDownloadUrl } from "../../api/pluginResults";
import type { PluginResult } from "../../types/domain";
import { displayValue, formatDateTime, formatDurationMs } from "../../utils/format";
import { statusTone } from "../../utils/status";

interface PluginResultTableProps {
  pluginResults: PluginResult[];
  limit?: number;
}

export function PluginResultTable({ pluginResults, limit = 100 }: PluginResultTableProps) {
  const visibleResults = pluginResults.slice(0, limit);
  const omittedCount = Math.max(pluginResults.length - visibleResults.length, 0);

  return (
    <div className="table-block">
      <Table caption="Volatility plugin execution metadata">
        <thead>
          <tr>
            <th>Plugin</th>
            <th>Category</th>
            <th>Status</th>
            <th>Duration</th>
            <th>Parsed rows</th>
            <th>Error summary</th>
            <th>Raw output</th>
            <th>Raw output key</th>
            <th>Parsed output key</th>
          </tr>
        </thead>
        <tbody>
          {visibleResults.map((pluginResult) => (
            <tr key={pluginResult.id}>
              <td className="long-text">
                <strong className="table-cell-title">{pluginResult.plugin_name}</strong>
                {pluginResult.source_plugin !== pluginResult.plugin_name && <span className="table-subtext">{pluginResult.source_plugin}</span>}
                {typeof pluginResult.extra_data?.cli_plugin_name === "string" && <span className="table-subtext">{pluginResult.extra_data.cli_plugin_name}</span>}
              </td>
              <td className="long-text">
                {displayValue(typeof pluginResult.extra_data?.plugin_category === "string" ? pluginResult.extra_data.plugin_category : null)}
                {typeof pluginResult.extra_data?.parser_strategy === "string" && <span className="table-subtext">Parser: {pluginResult.extra_data.parser_strategy}</span>}
                {typeof pluginResult.extra_data?.product_purpose === "string" && <span className="table-subtext">{pluginResult.extra_data.product_purpose}</span>}
              </td>
              <td><Badge tone={statusTone(pluginResult.status)}>{pluginResult.status}</Badge></td>
              <td>{formatDurationMs(pluginResult.duration_ms)}</td>
              <td>{pluginResult.parsed_record_count === null ? "Unknown" : pluginResult.parsed_record_count}</td>
              <td className="long-text error-summary">{displayValue(pluginResult.error_message)}</td>
              <td>
                {pluginResult.raw_output_key ? (
                  <a className="button button-secondary button-small" href={pluginRawOutputDownloadUrl(pluginResult.id)}>Download raw JSON</a>
                ) : (
                  <span className="muted">Not available</span>
                )}
              </td>
              <td className="long-text"><code className="code-value">{displayValue(pluginResult.raw_output_key)}</code></td>
              <td className="long-text">
                <code className="code-value">{displayValue(pluginResult.parsed_output_key)}</code>
                <span className="table-subtext">Completed: {formatDateTime(pluginResult.completed_at)}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </Table>
      {omittedCount > 0 && (
        <p className="table-note">Showing {visibleResults.length} of {pluginResults.length} plugin result rows.</p>
      )}
    </div>
  );
}
