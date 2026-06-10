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

export interface EvidenceMultipartUploadInitiatePayload {
  case_id: string;
  filename: string;
  size_bytes: number;
  content_type?: string | null;
  os_family?: OSFamily;
  os_version?: string | null;
  architecture?: string | null;
  kernel_version?: string | null;
  symbol_table?: string | null;
  acquisition_tool?: string | null;
  acquisition_time?: string | null;
  description?: string | null;
}

export interface EvidenceMultipartUploadInitiateResponse {
  upload_session_id: string;
  object_key: string;
  recommended_part_size_bytes: number;
  expected_part_count: number;
  max_size_bytes: number;
  expires_at: string | null;
}

export interface EvidenceMultipartPresignPartResponse {
  part_number: number;
  upload_url: string;
  expires_at: string | null;
}

export interface EvidenceMultipartPartCompleteResponse {
  upload_session_id: string;
  part_number: number;
  completed_parts: number;
  expected_part_count: number;
  uploaded_bytes: number;
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


export function initiateMultipartEvidenceUpload(
  payload: EvidenceMultipartUploadInitiatePayload,
): Promise<EvidenceMultipartUploadInitiateResponse> {
  return apiRequest<EvidenceMultipartUploadInitiateResponse>("/api/v1/evidences/multipart/initiate", {
    method: "POST",
    body: jsonBody(payload),
  });
}

export function presignMultipartEvidencePart(
  sessionId: string,
  partNumber: number,
): Promise<EvidenceMultipartPresignPartResponse> {
  return apiRequest<EvidenceMultipartPresignPartResponse>(`/api/v1/evidences/multipart/${sessionId}/presign-part`, {
    method: "POST",
    body: jsonBody({ part_number: partNumber }),
  });
}

export function recordMultipartEvidencePart(
  sessionId: string,
  partNumber: number,
  etag: string,
  sizeBytes: number,
): Promise<EvidenceMultipartPartCompleteResponse> {
  return apiRequest<EvidenceMultipartPartCompleteResponse>(`/api/v1/evidences/multipart/${sessionId}/parts`, {
    method: "POST",
    body: jsonBody({ part_number: partNumber, etag, size_bytes: sizeBytes }),
  });
}

export function completeMultipartEvidenceUpload(sessionId: string): Promise<Evidence> {
  return apiRequest<Evidence>(`/api/v1/evidences/multipart/${sessionId}/complete`, {
    method: "POST",
  });
}

export function cancelMultipartEvidenceUpload(sessionId: string): Promise<void> {
  return apiRequest<void>(`/api/v1/evidences/multipart/${sessionId}`, {
    method: "DELETE",
  });
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

