export type OSFamily = "windows" | "linux" | "unknown" | string;

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
  severity: string;
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

export interface ListResponse<T> {
  items: T[];
}
