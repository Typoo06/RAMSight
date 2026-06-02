import { apiRequest, jsonBody } from "./client";
import type { Case, ListResponse } from "../types/domain";

export interface CaseCreatePayload {
  case_code: string;
  name: string;
  description?: string | null;
  status?: string;
}

export interface CaseListParams {
  limit?: number;
  offset?: number;
}

export function listCases(params: CaseListParams = {}): Promise<ListResponse<Case>> {
  const query = new URLSearchParams();
  query.set("limit", String(params.limit ?? 50));
  query.set("offset", String(params.offset ?? 0));
  return apiRequest<ListResponse<Case>>(`/api/v1/cases?${query.toString()}`);
}

export function getCase(caseId: string): Promise<Case> {
  return apiRequest<Case>(`/api/v1/cases/${caseId}`);
}

export function createCase(payload: CaseCreatePayload): Promise<Case> {
  return apiRequest<Case>("/api/v1/cases", {
    method: "POST",
    body: jsonBody(payload),
  });
}
