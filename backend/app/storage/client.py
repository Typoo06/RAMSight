"""MinIO/S3 storage client wrapper."""

from dataclasses import dataclass
from pathlib import Path

from minio import Minio

from app.core.config import Settings, get_settings
from app.storage.hashing import FileHashResult, calculate_file_hashes
from app.storage.keys import evidence_object_key, parsed_plugin_output_key, raw_plugin_output_key, report_object_key
from app.storage.validation import normalize_safe_filename, validate_evidence_file


@dataclass(frozen=True)
class StorageObject:
    """Stored object reference."""

    bucket: str
    key: str
    size_bytes: int
    etag: str | None = None


@dataclass(frozen=True)
class EvidenceUploadResult:
    """Evidence upload result plus stream-calculated hashes."""

    storage_object: StorageObject
    safe_filename: str
    hashes: FileHashResult


class ObjectStorageClient:
    """Thin wrapper around MinIO for evidence and analysis output storage."""

    def __init__(self, settings: Settings | None = None, client: Minio | None = None) -> None:
        self.settings = settings or get_settings()
        self.client = client or Minio(
            self.settings.minio_endpoint,
            access_key=self.settings.minio_access_key,
            secret_key=self.settings.minio_secret_key,
            secure=self.settings.minio_secure,
        )

    @property
    def evidence_bucket(self) -> str:
        return self.settings.minio_bucket_evidence

    @property
    def raw_outputs_bucket(self) -> str:
        return self.settings.minio_bucket_raw_outputs

    @property
    def reports_bucket(self) -> str:
        return self.settings.minio_bucket_reports

    def ensure_buckets(self) -> None:
        """Create required buckets if they do not already exist."""
        for bucket in {self.evidence_bucket, self.raw_outputs_bucket, self.reports_bucket}:
            if not self.client.bucket_exists(bucket):
                self.client.make_bucket(bucket)

    def upload_file(self, bucket: str, object_key: str, path: Path, content_type: str | None = None) -> StorageObject:
        """Upload a local file to a specific bucket/key."""
        result = self.client.fput_object(bucket, object_key, str(path), content_type=content_type)
        return StorageObject(bucket=bucket, key=object_key, size_bytes=path.stat().st_size, etag=result.etag)

    def download_file(self, bucket: str, object_key: str, destination_path: Path) -> StorageObject:
        """Download an object to a local path."""
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        self.client.fget_object(bucket, object_key, str(destination_path))
        return StorageObject(bucket=bucket, key=object_key, size_bytes=destination_path.stat().st_size)

    def upload_evidence(
        self,
        case_id: object,
        evidence_id: object,
        path: Path,
        original_filename: str | None = None,
    ) -> EvidenceUploadResult:
        """Validate, hash, and upload a memory dump to the evidence bucket."""
        filename = original_filename or path.name
        validate_evidence_file(path, max_size_bytes=self.settings.evidence_max_upload_bytes)
        safe_filename = normalize_safe_filename(filename)
        object_key = evidence_object_key(case_id, evidence_id, safe_filename)
        hashes = calculate_file_hashes(path)
        storage_object = self.upload_file(self.evidence_bucket, object_key, path)
        return EvidenceUploadResult(storage_object=storage_object, safe_filename=safe_filename, hashes=hashes)

    def download_evidence(self, object_key: str, destination_path: Path) -> StorageObject:
        """Download evidence from the evidence bucket."""
        return self.download_file(self.evidence_bucket, object_key, destination_path)

    def upload_raw_plugin_output(
        self, case_id: object, job_id: object, plugin_name: str, path: Path
    ) -> StorageObject:
        """Upload raw plugin output JSON to the raw outputs bucket."""
        object_key = raw_plugin_output_key(case_id, job_id, plugin_name)
        return self.upload_file(self.raw_outputs_bucket, object_key, path, content_type="application/json")

    def upload_parsed_output(self, case_id: object, job_id: object, plugin_name: str, path: Path) -> StorageObject:
        """Upload parsed plugin output JSON to the raw outputs bucket."""
        object_key = parsed_plugin_output_key(case_id, job_id, plugin_name)
        return self.upload_file(self.raw_outputs_bucket, object_key, path, content_type="application/json")

    def upload_report(
        self, case_id: object, job_id: object, report_filename: str, path: Path, content_type: str | None = None
    ) -> StorageObject:
        """Upload a generated report artifact to the reports bucket."""
        object_key = report_object_key(case_id, job_id, report_filename)
        return self.upload_file(self.reports_bucket, object_key, path, content_type=content_type)


def get_storage_client() -> ObjectStorageClient:
    """Return a configured object storage client."""
    return ObjectStorageClient()
