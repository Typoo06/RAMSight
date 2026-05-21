# Minimal MinIO/S3 client wrapper used by worker tasks.

from dataclasses import dataclass
from pathlib import Path

from minio import Minio

from app.core.config import Settings, get_settings
from app.storage.keys import parsed_plugin_output_key, raw_plugin_output_key


@dataclass(frozen=True)
class StorageObject:

    bucket: str
    key: str
    size_bytes: int
    etag: str | None = None


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
    def raw_outputs_bucket(self) -> str:
        return self.settings.minio_bucket_raw_outputs

    def ensure_raw_outputs_bucket(self) -> None:
        if not self.client.bucket_exists(self.raw_outputs_bucket):
            self.client.make_bucket(self.raw_outputs_bucket)

    def download_file(self, bucket: str, object_key: str, destination_path: Path) -> StorageObject:
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        self.client.fget_object(bucket, object_key, str(destination_path))
        return StorageObject(bucket=bucket, key=object_key, size_bytes=destination_path.stat().st_size)

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
