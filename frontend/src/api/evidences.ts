import { apiRequest, jsonBody } from "./client";
import type { Evidence, ListResponse, OSFamily } from "../types/domain";

export interface EvidenceListParams {
  case_id?: string;
  limit?: number;
  offset?: number;
}

export interface EvidenceRegisterPayload {
  case_id: string;
  source_type: "minio_object" | "local_path" | string;
  original_filename: string;
  content_type?: string | null;
  size_bytes?: number | null;
  md5?: string | null;
  sha256?: string | null;
  storage_bucket?: string | null;
  storage_key?: string | null;
  local_path?: string | null;
  os_family?: OSFamily;
  os_version?: string | null;
  architecture?: string | null;
  kernel_version?: string | null;
  symbol_table?: string | null;
  acquisition_tool?: string | null;
  acquisition_time?: string | null;
}

export interface EvidenceChunkedUploadInitiatePayload {
  case_id: string;
  original_filename: string;
  size_bytes: number;
  os_family?: OSFamily;
  os_version?: string | null;
  architecture?: string | null;
  kernel_version?: string | null;
  symbol_table?: string | null;
  acquisition_tool?: string | null;
  acquisition_time?: string | null;
  chunk_size?: number | null;
}

export interface EvidenceChunkedUploadInitiateResponse {
  upload_id: string;
  chunk_size: number;
  max_size_bytes: number;
  total_chunks: number;
  expires_at: string | null;
}

export interface EvidenceChunkUploadResponse {
  upload_id: string;
  chunk_index: number;
  received_chunks: number;
  total_chunks: number;
  uploaded_bytes: number;
}

export function uploadEvidence(formData: FormData): Promise<Evidence> {
  return apiRequest<Evidence>("/api/v1/evidences/upload", {
    method: "POST",
    body: formData,
  });
}

export function registerEvidence(payload: EvidenceRegisterPayload): Promise<Evidence> {
  return apiRequest<Evidence>("/api/v1/evidences/register", {
    method: "POST",
    body: jsonBody(payload),
  });
}

export function initiateEvidenceUpload(
  payload: EvidenceChunkedUploadInitiatePayload,
): Promise<EvidenceChunkedUploadInitiateResponse> {
  return apiRequest<EvidenceChunkedUploadInitiateResponse>("/api/v1/evidences/uploads/initiate", {
    method: "POST",
    body: jsonBody(payload),
  });
}

export function uploadEvidenceChunk(
  uploadId: string,
  chunkIndex: number,
  chunk: Blob,
  signal?: AbortSignal,
): Promise<EvidenceChunkUploadResponse> {
  return apiRequest<EvidenceChunkUploadResponse>(`/api/v1/evidences/uploads/${uploadId}/chunks/${chunkIndex}`, {
    method: "PUT",
    headers: { "Content-Type": "application/octet-stream" },
    body: chunk,
    signal,
  });
}

export function completeEvidenceUpload(uploadId: string): Promise<Evidence> {
  return apiRequest<Evidence>(`/api/v1/evidences/uploads/${uploadId}/complete`, {
    method: "POST",
  });
}

export function cancelEvidenceUpload(uploadId: string): Promise<void> {
  return apiRequest<void>(`/api/v1/evidences/uploads/${uploadId}`, {
    method: "DELETE",
  });
}

export function listEvidences(params: EvidenceListParams = {}): Promise<ListResponse<Evidence>> {
  const query = new URLSearchParams();
  if (params.case_id) query.set("case_id", params.case_id);
  query.set("limit", String(params.limit ?? 100));
  query.set("offset", String(params.offset ?? 0));
  return apiRequest<ListResponse<Evidence>>(`/api/v1/evidences?${query.toString()}`);
}

export function getEvidence(evidenceId: string): Promise<Evidence> {
  return apiRequest<Evidence>(`/api/v1/evidences/${evidenceId}`);
}

