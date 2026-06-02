import { apiDownloadUrl, apiRequest } from "./client";
import type { IOC, ListResponse } from "../types/domain";

export type IOCExportFormat = "json" | "csv";

export interface IOCListParams {
  case_id?: string;
  job_id?: string;
  limit?: number;
  offset?: number;
}

export function listIOCs(params: IOCListParams = {}): Promise<ListResponse<IOC>> {
  const query = new URLSearchParams();
  if (params.case_id) query.set("case_id", params.case_id);
  if (params.job_id) query.set("job_id", params.job_id);
  query.set("limit", String(params.limit ?? 500));
  query.set("offset", String(params.offset ?? 0));
  return apiRequest<ListResponse<IOC>>(`/api/v1/iocs?${query.toString()}`);
}

export function iocExportDownloadUrl(jobId: string, format: IOCExportFormat): string {
  return apiDownloadUrl(`/api/v1/analysis-jobs/${jobId}/iocs/export.${format}`);
}
