# Direct-to-MinIO/S3 multipart evidence upload service.

from datetime import datetime, timedelta, timezone
import json
import math
import shutil
from pathlib import Path
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.models import Case, Evidence
from app.models.enums import EvidenceSourceType
from app.schemas.evidence import (
    EvidenceMultipartPartComplete,
    EvidenceMultipartPresignPartRequest,
    EvidenceMultipartUploadInitiate,
)
from app.services.errors import NotFoundError, ValidationError
from app.storage.hashing import calculate_stream_hashes
from app.storage.keys import evidence_object_key
from app.storage.validation import EvidenceValidationError, normalize_safe_filename, validate_evidence_extension
from app.storage.client import ObjectStorageClient

MANIFEST_FILENAME = "manifest.json"
DEFAULT_CONTENT_TYPE = "application/octet-stream"
MIN_S3_PART_SIZE_BYTES = 5 * 1024 * 1024
MAX_S3_PART_COUNT = 10000
PRESIGN_EXPIRY_SECONDS = 3600
HASH_STREAM_CHUNK_SIZE = 8 * 1024 * 1024


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _settings(settings: Settings | None = None) -> Settings:
    return settings or get_settings()


def _safe_session_id(session_id: UUID | str) -> str:
    try:
        return str(UUID(str(session_id)))
    except (TypeError, ValueError) as exc:
        raise ValidationError("invalid multipart upload session id") from exc


def _upload_root(settings: Settings) -> Path:
    root = Path(settings.evidence_upload_temp_dir).expanduser()
    if not root.is_absolute():
        raise ValidationError("evidence upload temp dir must be absolute")
    root.mkdir(parents=True, exist_ok=True)
    return root.resolve()


def _session_dir(session_id: UUID | str, settings: Settings) -> Path:
    safe_id = _safe_session_id(session_id)
    root = _upload_root(settings)
    session_dir = (root / safe_id).resolve()
    if session_dir.parent != root:
        raise ValidationError("invalid multipart upload session path")
    return session_dir


def _manifest_path(session_dir: Path) -> Path:
    return session_dir / MANIFEST_FILENAME


def _serialize_datetime(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _parse_datetime(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _write_manifest(session_dir: Path, manifest: dict) -> None:
    temp_path = session_dir / f".{MANIFEST_FILENAME}.tmp"
    temp_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    temp_path.replace(_manifest_path(session_dir))


def _load_manifest(session_id: UUID | str, settings: Settings, check_expiry: bool = True) -> tuple[Path, dict]:
    session_dir = _session_dir(session_id, settings)
    manifest_file = _manifest_path(session_dir)
    if not manifest_file.is_file():
        raise NotFoundError("multipart upload session not found")

    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValidationError("multipart upload session manifest is invalid") from exc

    if check_expiry:
        expires_at = _parse_datetime(manifest.get("expires_at"))
        if expires_at is not None and _utcnow() > expires_at:
            raise ValidationError("multipart upload session has expired")
    if manifest.get("status") != "active":
        raise ValidationError("multipart upload session is not active")
    return session_dir, manifest


def _part_size(settings: Settings) -> int:
    part_size = int(settings.evidence_multipart_part_size_bytes)
    if part_size < MIN_S3_PART_SIZE_BYTES:
        raise ValidationError("multipart part size must be at least 5242880 bytes")
    return part_size


def _expected_part_size(manifest: dict, part_number: int) -> int:
    size_bytes = int(manifest["size_bytes"])
    part_size = int(manifest["part_size_bytes"])
    offset = (part_number - 1) * part_size
    return min(part_size, size_bytes - offset)


def _validate_part_number(manifest: dict, part_number: int) -> None:
    expected_part_count = int(manifest["expected_part_count"])
    if part_number < 1 or part_number > expected_part_count:
        raise ValidationError("part number is outside the upload range")


def _clean_etag(value: str) -> str:
    etag = value.strip()
    if not etag or any(character in etag for character in "\r\n\t"):
        raise ValidationError("part ETag is invalid")
    return etag


def _uploaded_bytes(manifest: dict) -> int:
    total = 0
    for part_number_text, part in manifest.get("completed_parts", {}).items():
        try:
            part_number = int(part_number_text)
            total += int(part.get("size_bytes") or _expected_part_size(manifest, part_number))
        except (TypeError, ValueError):
            continue
    return total


def initiate_multipart_upload(
    db: Session,
    storage_client: ObjectStorageClient,
    data: EvidenceMultipartUploadInitiate,
    settings: Settings | None = None,
) -> dict:
    settings = _settings(settings)
    case = db.get(Case, data.case_id)
    if case is None:
        raise NotFoundError("case not found")

    try:
        safe_filename = normalize_safe_filename(data.filename)
        validate_evidence_extension(safe_filename)
    except EvidenceValidationError as exc:
        raise ValidationError(str(exc)) from exc

    if data.size_bytes > settings.evidence_max_upload_bytes:
        raise ValidationError("evidence file exceeds maximum upload size")

    part_size = _part_size(settings)
    expected_part_count = math.ceil(data.size_bytes / part_size)
    if expected_part_count > MAX_S3_PART_COUNT:
        raise ValidationError("multipart upload exceeds maximum supported part count")

    session_id = str(uuid4())
    evidence_id = str(uuid4())
    session_dir = _session_dir(session_id, settings)
    content_type = (data.content_type or DEFAULT_CONTENT_TYPE).strip() or DEFAULT_CONTENT_TYPE
    object_key = evidence_object_key(case.id, evidence_id, safe_filename)
    bucket = storage_client.evidence_bucket

    s3_upload_id: str | None = None
    try:
        s3_upload_id = storage_client.create_multipart_upload(bucket, object_key, content_type)
        session_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
        ttl_seconds = settings.evidence_upload_session_ttl_seconds
        expires_at = _utcnow() + timedelta(seconds=ttl_seconds) if ttl_seconds > 0 else None
        manifest = {
            "session_id": session_id,
            "status": "active",
            "case_id": str(case.id),
            "evidence_id": evidence_id,
            "original_filename": safe_filename,
            "content_type": content_type,
            "size_bytes": data.size_bytes,
            "part_size_bytes": part_size,
            "expected_part_count": expected_part_count,
            "completed_parts": {},
            "storage_bucket": bucket,
            "object_key": object_key,
            "s3_upload_id": s3_upload_id,
            "os_family": data.os_family.value,
            "os_version": data.os_version,
            "architecture": data.architecture,
            "kernel_version": data.kernel_version,
            "symbol_table": data.symbol_table,
            "acquisition_tool": data.acquisition_tool,
            "acquisition_time": _serialize_datetime(data.acquisition_time),
            "description": data.description,
            "created_at": _serialize_datetime(_utcnow()),
            "expires_at": _serialize_datetime(expires_at),
        }
        _write_manifest(session_dir, manifest)
    except Exception:
        if s3_upload_id:
            try:
                storage_client.abort_multipart_upload(bucket, object_key, s3_upload_id)
            except Exception:
                pass
        shutil.rmtree(session_dir, ignore_errors=True)
        raise

    return {
        "upload_session_id": session_id,
        "object_key": object_key,
        "recommended_part_size_bytes": part_size,
        "expected_part_count": expected_part_count,
        "max_size_bytes": settings.evidence_max_upload_bytes,
        "expires_at": expires_at,
    }


def presign_upload_part(
    storage_client: ObjectStorageClient,
    session_id: UUID | str,
    data: EvidenceMultipartPresignPartRequest,
    settings: Settings | None = None,
) -> dict:
    settings = _settings(settings)
    _, manifest = _load_manifest(session_id, settings)
    part_number = data.part_number
    _validate_part_number(manifest, part_number)
    expires_at = _utcnow() + timedelta(seconds=PRESIGN_EXPIRY_SECONDS)
    upload_url = storage_client.presign_upload_part(
        manifest["storage_bucket"],
        manifest["object_key"],
        manifest["s3_upload_id"],
        part_number,
        PRESIGN_EXPIRY_SECONDS,
    )
    return {"part_number": part_number, "upload_url": upload_url, "expires_at": expires_at}


def record_completed_part(
    session_id: UUID | str,
    data: EvidenceMultipartPartComplete,
    settings: Settings | None = None,
) -> dict:
    settings = _settings(settings)
    session_dir, manifest = _load_manifest(session_id, settings)
    part_number = data.part_number
    _validate_part_number(manifest, part_number)
    expected_size = _expected_part_size(manifest, part_number)
    if data.size_bytes is not None and data.size_bytes != expected_size:
        raise ValidationError("part size does not match expected range")

    etag = _clean_etag(data.etag)
    completed_parts = manifest.setdefault("completed_parts", {})
    completed_parts[str(part_number)] = {
        "part_number": part_number,
        "etag": etag,
        "size_bytes": data.size_bytes if data.size_bytes is not None else expected_size,
        "completed_at": _serialize_datetime(_utcnow()),
    }
    _write_manifest(session_dir, manifest)
    return {
        "upload_session_id": _safe_session_id(session_id),
        "part_number": part_number,
        "completed_parts": len(completed_parts),
        "expected_part_count": int(manifest["expected_part_count"]),
        "uploaded_bytes": _uploaded_bytes(manifest),
    }


def complete_multipart_upload(
    db: Session,
    storage_client: ObjectStorageClient,
    session_id: UUID | str,
    settings: Settings | None = None,
) -> Evidence:
    settings = _settings(settings)
    session_dir, manifest = _load_manifest(session_id, settings)
    completed_parts = manifest.get("completed_parts", {})
    expected_part_count = int(manifest["expected_part_count"])
    missing_parts = [part_number for part_number in range(1, expected_part_count + 1) if str(part_number) not in completed_parts]
    if missing_parts:
        raise ValidationError("multipart upload is missing parts")

    sorted_parts: list[dict[str, object]] = []
    for part_number in range(1, expected_part_count + 1):
        part = completed_parts[str(part_number)]
        expected_size = _expected_part_size(manifest, part_number)
        if int(part.get("size_bytes") or 0) != expected_size:
            raise ValidationError("multipart upload part manifest is invalid")
        sorted_parts.append({"part_number": part_number, "etag": _clean_etag(str(part["etag"]))})

    case = db.get(Case, UUID(manifest["case_id"]))
    if case is None:
        raise NotFoundError("case not found")

    bucket = manifest["storage_bucket"]
    object_key = manifest["object_key"]
    storage_completed = False
    try:
        storage_client.complete_multipart_upload(bucket, object_key, manifest["s3_upload_id"], sorted_parts)
        storage_completed = True
        hashes = calculate_stream_hashes(storage_client.iter_object_chunks(bucket, object_key, HASH_STREAM_CHUNK_SIZE))
        if hashes.size_bytes != int(manifest["size_bytes"]):
            raise ValidationError("uploaded object size does not match the declared size")

        evidence = Evidence(
            id=UUID(manifest["evidence_id"]),
            case_id=case.id,
            source_type=EvidenceSourceType.UPLOAD.value,
            original_filename=manifest["original_filename"],
            content_type=manifest.get("content_type") or DEFAULT_CONTENT_TYPE,
            size_bytes=hashes.size_bytes,
            md5=hashes.md5,
            sha256=hashes.sha256,
            storage_bucket=bucket,
            storage_key=object_key,
            os_family=manifest.get("os_family") or "unknown",
            os_version=manifest.get("os_version"),
            architecture=manifest.get("architecture"),
            kernel_version=manifest.get("kernel_version"),
            symbol_table=manifest.get("symbol_table"),
            acquisition_tool=manifest.get("acquisition_tool"),
            acquisition_time=_parse_datetime(manifest.get("acquisition_time")),
        )
        db.add(evidence)
        db.commit()
        db.refresh(evidence)
        shutil.rmtree(session_dir, ignore_errors=True)
        return evidence
    except Exception:
        db.rollback()
        if storage_completed:
            try:
                storage_client.delete_object(bucket, object_key)
            except Exception:
                pass
        raise


def abort_multipart_upload(
    storage_client: ObjectStorageClient,
    session_id: UUID | str,
    settings: Settings | None = None,
) -> None:
    settings = _settings(settings)
    session_dir, manifest = _load_manifest(session_id, settings, check_expiry=False)
    try:
        storage_client.abort_multipart_upload(
            manifest["storage_bucket"],
            manifest["object_key"],
            manifest["s3_upload_id"],
        )
    finally:
        shutil.rmtree(session_dir, ignore_errors=True)
