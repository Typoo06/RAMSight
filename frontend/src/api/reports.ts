import { apiDownloadUrl, apiRequest } from "./client";
import type { ListResponse, Report } from "../types/domain";

export interface ReportListParams {
  case_id?: string;
  job_id?: string;
  limit?: number;
  offset?: number;
}

export function listReports(params: ReportListParams = {}): Promise<ListResponse<Report>> {
  const query = new URLSearchParams();
  if (params.case_id) query.set("case_id", params.case_id);
  if (params.job_id) query.set("job_id", params.job_id);
  query.set("limit", String(params.limit ?? 100));
  query.set("offset", String(params.offset ?? 0));
  return apiRequest<ListResponse<Report>>(`/api/v1/reports?${query.toString()}`);
}

export function getReport(reportId: string): Promise<Report> {
  return apiRequest<Report>(`/api/v1/reports/${reportId}`);
}

export function reportDownloadUrl(reportId: string): string {
  return apiDownloadUrl(`/api/v1/reports/${reportId}/download`);
}
