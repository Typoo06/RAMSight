# Storage integration package.

from app.storage.client import EvidenceUploadResult, ObjectStorageClient, StorageObject, get_storage_client
from app.storage.hashing import FileHashResult, calculate_file_hashes
from app.storage.keys import evidence_object_key, parsed_plugin_output_key, raw_plugin_output_key, report_object_key
from app.storage.validation import EvidenceValidationError, normalize_safe_filename, validate_evidence_file

__all__ = [
    "EvidenceUploadResult",
    "EvidenceValidationError",
    "FileHashResult",
    "ObjectStorageClient",
    "StorageObject",
    "calculate_file_hashes",
    "evidence_object_key",
    "get_storage_client",
    "normalize_safe_filename",
    "parsed_plugin_output_key",
    "raw_plugin_output_key",
    "report_object_key",
    "validate_evidence_file",
]
