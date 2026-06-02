import { apiRequest, jsonBody } from "./client";
import type { AnalystNote, ListResponse, RiskFinding } from "../types/domain";

export interface RiskFindingListParams {
  case_id?: string;
  job_id?: string;
  review_status?: string;
  analyst_verdict?: string;
  severity_effective?: string;
  limit?: number;
  offset?: number;
}

export interface RiskFindingReviewPayload {
  review_status?: string | null;
  analyst_verdict?: string | null;
  severity_override?: string | null;
  reviewed_by_name?: string | null;
  note?: string | null;
}

export interface AnalystNotePayload {
  content: string;
  author_name?: string | null;
  note_type?: string | null;
}

export function listRiskFindings(params: RiskFindingListParams = {}): Promise<ListResponse<RiskFinding>> {
  const query = new URLSearchParams();
  if (params.case_id) query.set("case_id", params.case_id);
  if (params.job_id) query.set("job_id", params.job_id);
  if (params.review_status) query.set("review_status", params.review_status);
  if (params.analyst_verdict) query.set("analyst_verdict", params.analyst_verdict);
  if (params.severity_effective) query.set("severity_effective", params.severity_effective);
  query.set("limit", String(params.limit ?? 500));
  query.set("offset", String(params.offset ?? 0));
  return apiRequest<ListResponse<RiskFinding>>(`/api/v1/risk-findings?${query.toString()}`);
}

export function updateRiskFindingReview(findingId: string, payload: RiskFindingReviewPayload): Promise<RiskFinding> {
  return apiRequest<RiskFinding>(`/api/v1/risk-findings/${findingId}/review`, {
    method: "PATCH",
    body: jsonBody(payload),
  });
}

export function listRiskFindingNotes(findingId: string): Promise<ListResponse<AnalystNote>> {
  return apiRequest<ListResponse<AnalystNote>>(`/api/v1/risk-findings/${findingId}/notes`);
}

export function createRiskFindingNote(findingId: string, payload: AnalystNotePayload): Promise<AnalystNote> {
  return apiRequest<AnalystNote>(`/api/v1/risk-findings/${findingId}/notes`, {
    method: "POST",
    body: jsonBody(payload),
  });
}
