# Evidence files are validated before upload and stored outside PostgreSQL.

ALLOWED_EVIDENCE_EXTENSIONS = frozenset({".raw", ".mem", ".vmem", ".dmp", ".lime"})
DEFAULT_HASH_CHUNK_SIZE = 1024 * 1024

