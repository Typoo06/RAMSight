import { apiDownloadUrl, apiRequest } from "./client";
import type { ListResponse, PluginResult } from "../types/domain";

export interface PluginResultListParams {
  status?: string;
  plugin_name?: string;
  source_plugin?: string;
  limit?: number;
  offset?: number;
}

export function listPluginResults(jobId: string, params: PluginResultListParams = {}): Promise<ListResponse<PluginResult>> {
  const query = new URLSearchParams();
  if (params.status) query.set("status", params.status);
  if (params.plugin_name) query.set("plugin_name", params.plugin_name);
  if (params.source_plugin) query.set("source_plugin", params.source_plugin);
  query.set("limit", String(params.limit ?? 100));
  query.set("offset", String(params.offset ?? 0));
  return apiRequest<ListResponse<PluginResult>>(`/api/v1/analysis-jobs/${jobId}/plugin-results?${query.toString()}`);
}

export function getPluginResult(pluginResultId: string): Promise<PluginResult> {
  return apiRequest<PluginResult>(`/api/v1/plugin-results/${pluginResultId}`);
}


export function pluginResultsExportDownloadUrl(jobId: string, params: PluginResultListParams = {}): string {
  const query = new URLSearchParams();
  if (params.status) query.set("status", params.status);
  if (params.plugin_name) query.set("plugin_name", params.plugin_name);
  if (params.source_plugin) query.set("source_plugin", params.source_plugin);
  return apiDownloadUrl(`/api/v1/analysis-jobs/${jobId}/plugin-results/export.json?${query.toString()}`);
}

export function pluginRawOutputDownloadUrl(pluginResultId: string): string {
  return apiDownloadUrl(`/api/v1/plugin-results/${pluginResultId}/raw-output/download`);
}
