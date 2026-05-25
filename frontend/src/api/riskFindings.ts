import { apiRequest } from "./client";
import type { ListResponse, RiskFinding } from "../types/domain";

export interface RiskFindingListParams {
  case_id?: string;
  job_id?: string;
  limit?: number;
  offset?: number;
}

export function listRiskFindings(params: RiskFindingListParams = {}): Promise<ListResponse<RiskFinding>> {
  const query = new URLSearchParams();
  if (params.case_id) query.set("case_id", params.case_id);
  if (params.job_id) query.set("job_id", params.job_id);
  query.set("limit", String(params.limit ?? 500));
  query.set("offset", String(params.offset ?? 0));
  return apiRequest<ListResponse<RiskFinding>>(`/api/v1/risk-findings?${query.toString()}`);
}

