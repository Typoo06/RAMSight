# MinIO/S3 client wrapper for evidence and generated analysis artifacts.

from dataclasses import dataclass
from collections.abc import Iterator
from pathlib import Path

from minio import Minio
from minio.error import S3Error

from app.core.config import Settings, get_settings
from app.storage.hashing import FileHashResult, calculate_file_hashes
from app.storage.keys import (
    evidence_object_key,
    ioc_export_key,
    parsed_plugin_output_key,
    raw_plugin_output_key,
    report_object_key,
)
from app.storage.validation import normalize_safe_filename, validate_evidence_extension, validate_evidence_file


@dataclass(frozen=True)
class StorageObject:

    bucket: str
    key: str
    size_bytes: int
    etag: str | None = None


class StorageDownloadError(Exception):
    pass


class StorageObjectNotFoundError(StorageDownloadError):
    pass


@dataclass(frozen=True)
class StorageObjectStream:

    bucket: str
    key: str
    response: object
    size_bytes: int | None = None
    content_type: str | None = None

    def iter_chunks(self, chunk_size: int = 1024 * 1024) -> Iterator[bytes]:
        try:
            yield from self.response.stream(chunk_size)  # type: ignore[attr-defined]
        finally:
            self.close()

    def close(self) -> None:
        close = getattr(self.response, "close", None)
        release_conn = getattr(self.response, "release_conn", None)
        if callable(close):
            close()
        if callable(release_conn):
            release_conn()


@dataclass(frozen=True)
class EvidenceUploadResult:

    safe_filename: str
    hashes: FileHashResult
    storage_object: StorageObject


class ObjectStorageClient:

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

    def ensure_bucket(self, bucket_name: str) -> None:
        if not self.client.bucket_exists(bucket_name):
            self.client.make_bucket(bucket_name)

    def ensure_evidence_bucket(self) -> None:
        self.ensure_bucket(self.evidence_bucket)

    def ensure_raw_outputs_bucket(self) -> None:
        self.ensure_bucket(self.raw_outputs_bucket)

    def ensure_reports_bucket(self) -> None:
        self.ensure_bucket(self.reports_bucket)

    def ensure_buckets(self) -> None:
        self.ensure_evidence_bucket()
        self.ensure_raw_outputs_bucket()
        self.ensure_reports_bucket()

    def download_file(self, bucket: str, object_key: str, destination_path: Path) -> StorageObject:
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        self.client.fget_object(bucket, object_key, str(destination_path))
        return StorageObject(bucket=bucket, key=object_key, size_bytes=destination_path.stat().st_size)

    def open_object_stream(self, bucket: str, object_key: str) -> StorageObjectStream:
        try:
            response = self.client.get_object(bucket, object_key)
        except S3Error as exc:
            if exc.code in {"NoSuchBucket", "NoSuchKey", "NoSuchObject", "NoSuchVersion"}:
                raise StorageObjectNotFoundError("storage object not found") from exc
            raise StorageDownloadError("storage object could not be downloaded") from exc
        except Exception as exc:
            raise StorageDownloadError("storage object could not be downloaded") from exc

        headers = getattr(response, "headers", {}) or {}
        content_length = headers.get("Content-Length") or headers.get("content-length")
        try:
            size_bytes = int(content_length) if content_length is not None else None
        except (TypeError, ValueError):
            size_bytes = None
        content_type = headers.get("Content-Type") or headers.get("content-type")
        return StorageObjectStream(
            bucket=bucket,
            key=object_key,
            response=response,
            size_bytes=size_bytes,
            content_type=content_type,
        )

    def upload_evidence(
        self,
        case_id: object,
        evidence_id: object,
        path: Path,
        original_filename: str,
    ) -> EvidenceUploadResult:
        safe_filename = normalize_safe_filename(original_filename)
        validate_evidence_extension(safe_filename)
        validate_evidence_file(path, max_size_bytes=self.settings.evidence_max_upload_bytes)
        hashes = calculate_file_hashes(path)

        self.ensure_evidence_bucket()
        object_key = evidence_object_key(case_id, evidence_id, safe_filename)
        result = self.client.fput_object(
            self.evidence_bucket,
            object_key,
            str(path),
            content_type="application/octet-stream",
        )
        storage_object = StorageObject(
            bucket=self.evidence_bucket,
            key=object_key,
            size_bytes=hashes.size_bytes,
            etag=result.etag,
        )
        return EvidenceUploadResult(safe_filename=safe_filename, hashes=hashes, storage_object=storage_object)

    def upload_raw_plugin_output(
        self,
        case_id: object,
        job_id: object,
        plugin_name: str,
        path: Path,
    ) -> StorageObject:
        self.ensure_raw_outputs_bucket()
        object_key = raw_plugin_output_key(case_id, job_id, plugin_name)
        result = self.client.fput_object(
            self.raw_outputs_bucket,
            object_key,
            str(path),
            content_type="application/json",
        )
        return StorageObject(
            bucket=self.raw_outputs_bucket,
            key=object_key,
            size_bytes=path.stat().st_size,
            etag=result.etag,
        )

    def upload_parsed_output(self, case_id: object, job_id: object, plugin_name: str, path: Path) -> StorageObject:
        self.ensure_raw_outputs_bucket()
        object_key = parsed_plugin_output_key(case_id, job_id, plugin_name)
        result = self.client.fput_object(
            self.raw_outputs_bucket,
            object_key,
            str(path),
            content_type="application/json",
        )
        return StorageObject(
            bucket=self.raw_outputs_bucket,
            key=object_key,
            size_bytes=path.stat().st_size,
            etag=result.etag,
        )

    def upload_ioc_export(
        self,
        case_id: object,
        job_id: object,
        filename: str,
        path: Path,
        content_type: str,
    ) -> StorageObject:
        self.ensure_raw_outputs_bucket()
        object_key = ioc_export_key(case_id, job_id, filename)
        result = self.client.fput_object(
            self.raw_outputs_bucket,
            object_key,
            str(path),
            content_type=content_type,
        )
        return StorageObject(
            bucket=self.raw_outputs_bucket,
            key=object_key,
            size_bytes=path.stat().st_size,
            etag=result.etag,
        )

    def upload_report(
        self,
        case_id: object,
        job_id: object,
        filename: str,
        path: Path,
        content_type: str,
    ) -> StorageObject:
        self.ensure_reports_bucket()
        object_key = report_object_key(case_id, job_id, filename)
        result = self.client.fput_object(
            self.reports_bucket,
            object_key,
            str(path),
            content_type=content_type,
        )
        return StorageObject(
            bucket=self.reports_bucket,
            key=object_key,
            size_bytes=path.stat().st_size,
            etag=result.etag,
        )


def get_storage_client() -> ObjectStorageClient:
    return ObjectStorageClient()
