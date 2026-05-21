"""Storage constants for evidence and generated analysis outputs."""

ALLOWED_EVIDENCE_EXTENSIONS = frozenset({".raw", ".mem", ".vmem", ".dmp", ".lime"})
DEFAULT_HASH_CHUNK_SIZE = 1024 * 1024
DEFAULT_EVIDENCE_MAX_UPLOAD_BYTES = 21474836480

EVIDENCE_BUCKET_SETTING = "minio_bucket_evidence"
RAW_OUTPUTS_BUCKET_SETTING = "minio_bucket_raw_outputs"
REPORTS_BUCKET_SETTING = "minio_bucket_reports"
