import { apiRequest } from "./client";
import type {
  CommandArtifact,
  ListResponse,
  MemoryRegionArtifact,
  ModuleArtifact,
  NetworkArtifact,
  ProcessArtifact,
  YaraMatchArtifact,
} from "../types/domain";

export interface ArtifactListParams {
  pid?: number;
  process_name?: string;
  source_plugin?: string;
  limit?: number;
  offset?: number;
}

export interface NetworkArtifactListParams extends ArtifactListParams {
  remote_address?: string;
  protocol?: string;
}

export interface MemoryRegionArtifactListParams extends ArtifactListParams {
  executable_only?: boolean;
  suspicious_only?: boolean;
}

export interface YaraMatchListParams {
  pid?: number;
  source_plugin?: string;
  rule_name?: string;
  target_identifier?: string;
  limit?: number;
  offset?: number;
}

type ArtifactQueryParams =
  | ArtifactListParams
  | NetworkArtifactListParams
  | MemoryRegionArtifactListParams
  | YaraMatchListParams;

function artifactQuery(params: ArtifactQueryParams): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params) as Array<[string, string | number | boolean | undefined]>) {
    if (value === undefined || value === "") continue;
    query.set(key, String(value));
  }
  query.set("limit", String(params.limit ?? 100));
  query.set("offset", String(params.offset ?? 0));
  return query.toString();
}

export function listProcessArtifacts(jobId: string, params: ArtifactListParams = {}): Promise<ListResponse<ProcessArtifact>> {
  return apiRequest<ListResponse<ProcessArtifact>>(`/api/v1/analysis-jobs/${jobId}/artifacts/processes?${artifactQuery(params)}`);
}

export function listCommandArtifacts(jobId: string, params: ArtifactListParams = {}): Promise<ListResponse<CommandArtifact>> {
  return apiRequest<ListResponse<CommandArtifact>>(`/api/v1/analysis-jobs/${jobId}/artifacts/commands?${artifactQuery(params)}`);
}

export function listNetworkArtifacts(jobId: string, params: NetworkArtifactListParams = {}): Promise<ListResponse<NetworkArtifact>> {
  return apiRequest<ListResponse<NetworkArtifact>>(`/api/v1/analysis-jobs/${jobId}/artifacts/network?${artifactQuery(params)}`);
}

export function listModuleArtifacts(jobId: string, params: ArtifactListParams = {}): Promise<ListResponse<ModuleArtifact>> {
  return apiRequest<ListResponse<ModuleArtifact>>(`/api/v1/analysis-jobs/${jobId}/artifacts/modules?${artifactQuery(params)}`);
}

export function listMemoryRegionArtifacts(jobId: string, params: MemoryRegionArtifactListParams = {}): Promise<ListResponse<MemoryRegionArtifact>> {
  return apiRequest<ListResponse<MemoryRegionArtifact>>(`/api/v1/analysis-jobs/${jobId}/artifacts/memory-regions?${artifactQuery(params)}`);
}

export function listYaraMatches(jobId: string, params: YaraMatchListParams = {}): Promise<ListResponse<YaraMatchArtifact>> {
  return apiRequest<ListResponse<YaraMatchArtifact>>(`/api/v1/analysis-jobs/${jobId}/artifacts/yara-matches?${artifactQuery(params)}`);
}
