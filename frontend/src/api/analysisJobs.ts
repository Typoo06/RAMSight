import { apiRequest, jsonBody } from "./client";
import type { AnalysisJob, AnalysisJobStatus, ListResponse, OSFamily } from "../types/domain";

export interface AnalysisJobCreatePayload {
  case_id: string;
  evidence_id: string;
  os_family?: OSFamily;
  os_version?: string | null;
  architecture?: string | null;
  kernel_version?: string | null;
  symbol_table?: string | null;
  plugin_profile?: string | null;
  requested_plugins?: string[] | null;
}

export interface AnalysisJobListParams {
  case_id?: string;
  limit?: number;
  offset?: number;
}

export function createAnalysisJob(payload: AnalysisJobCreatePayload): Promise<AnalysisJob> {
  return apiRequest<AnalysisJob>("/api/v1/analysis-jobs", {
    method: "POST",
    body: jsonBody(payload),
  });
}

export function listAnalysisJobs(params: AnalysisJobListParams = {}): Promise<ListResponse<AnalysisJob>> {
  const query = new URLSearchParams();
  if (params.case_id) query.set("case_id", params.case_id);
  query.set("limit", String(params.limit ?? 100));
  query.set("offset", String(params.offset ?? 0));
  return apiRequest<ListResponse<AnalysisJob>>(`/api/v1/analysis-jobs?${query.toString()}`);
}

export function getAnalysisJob(jobId: string): Promise<AnalysisJob> {
  return apiRequest<AnalysisJob>(`/api/v1/analysis-jobs/${jobId}`);
}

export function getAnalysisJobStatus(jobId: string): Promise<AnalysisJobStatus> {
  return apiRequest<AnalysisJobStatus>(`/api/v1/analysis-jobs/${jobId}/status`);
}

