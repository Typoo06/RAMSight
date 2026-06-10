export type OSFamily = "windows" | "linux" | "unknown" | string;
export type AnalysisPluginProfile =
  | "windows_default"
  | "windows_memory_yara"
  | "windows_memory_yara_elastic"
  | "windows_memory_yara_neo23x0"
  | "windows_memory_yara_third_party_all"
  | "windows_memory_deep"
  | "windows_memory_deep_yara_elastic"
  | "windows_memory_deep_yara_neo23x0"
  | "windows_memory_deep_yara_third_party_all"
  | "windows_malware_evasion"
  | "windows_kernel_rootkit"
  | "windows_investigation_context";
export type ReviewStatus = "new" | "investigating" | "reviewed";
export type AnalystVerdict = "true_positive" | "false_positive" | "benign" | "suspicious" | "needs_more_evidence" | "ignored";
export type Severity = "low" | "medium" | "high" | "critical" | string;

export interface Case {
  id: string;
  case_code: string;
  name: string;
  description: string | null;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface Evidence {
  id: string;
  case_id: string;
  uploaded_by_id: string | null;
  source_type: string;
  original_filename: string;
  content_type: string | null;
  size_bytes: number | null;
  md5: string | null;
  sha256: string | null;
  storage_bucket: string | null;
  storage_key: string | null;
  local_path: string | null;
  os_family: OSFamily;
  os_version: string | null;
  architecture: string | null;
  kernel_version: string | null;
  symbol_table: string | null;
  acquisition_tool: string | null;
  acquisition_time: string | null;
  created_at: string;
  updated_at: string;
}

export interface AnalysisJob {
  id: string;
  case_id: string;
  evidence_id: string;
  created_by_id: string | null;
  status: string;
  os_family: OSFamily;
  os_version: string | null;
  architecture: string | null;
  kernel_version: string | null;
  symbol_table: string | null;
  plugin_profile: string | null;
  requested_plugins: string[] | null;
  error_message: string | null;
  duration_ms: number | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface AnalysisJobStatus {
  id: string;
  status: string;
  error_message: string | null;
  duration_ms: number | null;
  started_at: string | null;
  completed_at: string | null;
  updated_at: string;
}

export interface IOC {
  id: string;
  analysis_job_id: string;
  evidence_id: string;
  risk_finding_id: string | null;
  os_family: OSFamily;
  source_plugin: string | null;
  ioc_type: string;
  value: string;
  normalized_value: string | null;
  context: string | null;
  confidence: number | null;
  extra_data: Record<string, unknown> | null;
  created_at: string;
  updated_at: string;
}

export interface RiskFinding {
  id: string;
  analysis_job_id: string;
  evidence_id: string;
  plugin_result_id: string | null;
  os_family: OSFamily;
  os_scope: string;
  source_plugin: string | null;
  rule_id: string | null;
  rule_name: string | null;
  category: string | null;
  severity: Severity;
  effective_severity?: Severity;
  review_status?: ReviewStatus | string | null;
  analyst_verdict?: AnalystVerdict | string | null;
  severity_override?: Severity | null;
  reviewed_at?: string | null;
  reviewed_by_name?: string | null;
  review_updated_at?: string | null;
  score: number;
  title: string;
  description: string | null;
  artifact_type: string | null;
  artifact_id: string | null;
  recommendation: string | null;
  extra_data: Record<string, unknown> | null;
  created_at: string;
  updated_at: string;
}

export interface AnalystNote {
  id: string;
  case_id: string;
  evidence_id: string | null;
  analysis_job_id: string | null;
  risk_finding_id: string | null;
  note_type: string;
  author_name: string | null;
  content: string;
  created_at: string;
  updated_at: string;
}

export interface Report {
  id: string;
  case_id: string;
  evidence_id: string;
  analysis_job_id: string;
  os_family: OSFamily;
  report_type: string;
  format: string;
  storage_bucket: string | null;
  storage_key: string | null;
  generated_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface PluginResult {
  id: string;
  analysis_job_id: string;
  evidence_id: string;
  os_family: OSFamily;
  plugin_profile: string | null;
  plugin_name: string;
  source_plugin: string;
  status: string;
  raw_output_bucket: string | null;
  raw_output_key: string | null;
  parsed_output_bucket: string | null;
  parsed_output_key: string | null;
  parsed_record_count: number | null;
  error_message: string | null;
  duration_ms: number | null;
  extra_data: Record<string, unknown> | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface ArtifactBase {
  id: string;
  analysis_job_id: string;
  evidence_id: string;
  plugin_result_id: string | null;
  os_family: OSFamily;
  source_plugin: string | null;
  created_at: string;
}

export interface ProcessArtifact extends ArtifactBase {
  pid: number | null;
  ppid: number | null;
  name: string | null;
  image_path: string | null;
  command_line: string | null;
  user_name: string | null;
  session_id: number | null;
  created_time: string | null;
  exited_time: string | null;
  is_hidden_candidate: boolean;
}

export interface CommandArtifact extends ArtifactBase {
  pid: number | null;
  process_name: string | null;
  command: string | null;
  shell_type: string | null;
  user_name: string | null;
  executed_at: string | null;
}

export interface NetworkArtifact extends ArtifactBase {
  protocol: string | null;
  local_address: string | null;
  local_port: number | null;
  remote_address: string | null;
  remote_port: number | null;
  state: string | null;
  pid: number | null;
  process_name: string | null;
  created_time: string | null;
}

export interface ModuleArtifact extends ArtifactBase {
  pid: number | null;
  process_name: string | null;
  module_name: string | null;
  module_path: string | null;
  base_address: string | null;
  size_bytes: number | null;
  load_time: string | null;
}

export interface MemoryRegionArtifact extends ArtifactBase {
  pid: number | null;
  process_name: string | null;
  start_address: string | null;
  end_address: string | null;
  protection: string | null;
  is_executable: boolean;
  is_private: boolean;
  description: string | null;
  hexdump_excerpt: string | null;
  disassembly_excerpt: string | null;
}

export interface YaraMatchArtifact {
  id: string;
  analysis_job_id: string;
  evidence_id: string;
  plugin_result_id: string | null;
  os_family: OSFamily;
  source_plugin: string | null;
  rule_name: string;
  namespace: string | null;
  tags: string[] | null;
  target_type: string | null;
  target_identifier: string | null;
  offset: number | null;
  matched_text_excerpt: string | null;
  extra_data: Record<string, unknown> | null;
  created_at: string;
}

export interface ListResponse<T> {
  items: T[];
  total?: number | null;
  limit?: number | null;
  offset?: number | null;
}
