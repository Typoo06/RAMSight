# Browser chunked evidence upload session service.

from collections.abc import AsyncIterator
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
from app.schemas.evidence import EvidenceChunkedUploadInitiate
from app.services.errors import NotFoundError, ValidationError
from app.storage.client import ObjectStorageClient
from app.storage.validation import EvidenceValidationError, normalize_safe_filename, validate_evidence_extension

MANIFEST_FILENAME = "manifest.json"
EVIDENCE_TEMP_FILENAME = "evidence.tmp"
CHUNK_COPY_BUFFER_BYTES = 1024 * 1024
CHUNK_CONTENT_TYPE = "application/octet-stream"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _settings(settings: Settings | None = None) -> Settings:
    return settings or get_settings()


def _safe_upload_id(upload_id: UUID | str) -> str:
    try:
        return str(UUID(str(upload_id)))
    except (TypeError, ValueError) as exc:
        raise ValidationError("invalid upload session id") from exc


def _upload_root(settings: Settings) -> Path:
    root = Path(settings.evidence_upload_temp_dir).expanduser()
    if not root.is_absolute():
        raise ValidationError("evidence upload temp dir must be absolute")
    root.mkdir(parents=True, exist_ok=True)
    return root.resolve()


def _session_dir(upload_id: UUID | str, settings: Settings) -> Path:
    safe_id = _safe_upload_id(upload_id)
    root = _upload_root(settings)
    session_dir = (root / safe_id).resolve()
    if session_dir.parent != root:
        raise ValidationError("invalid upload session path")
    return session_dir


def _manifest_path(session_dir: Path) -> Path:
    return session_dir / MANIFEST_FILENAME


def _evidence_temp_path(session_dir: Path) -> Path:
    return session_dir / EVIDENCE_TEMP_FILENAME


def _serialize_datetime(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _parse_datetime(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _write_manifest(session_dir: Path, manifest: dict) -> None:
    temp_path = session_dir / f".{MANIFEST_FILENAME}.tmp"
    temp_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    temp_path.replace(_manifest_path(session_dir))


def _load_manifest(upload_id: UUID | str, settings: Settings) -> tuple[Path, dict]:
    session_dir = _session_dir(upload_id, settings)
    manifest_file = _manifest_path(session_dir)
    if not manifest_file.is_file():
        raise NotFoundError("upload session not found")

    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValidationError("upload session manifest is invalid") from exc

    expires_at = _parse_datetime(manifest.get("expires_at"))
    if expires_at is not None and _utcnow() > expires_at:
        shutil.rmtree(session_dir, ignore_errors=True)
        raise ValidationError("upload session has expired")
    return session_dir, manifest


def _expected_chunk_size(manifest: dict, chunk_index: int) -> int:
    size_bytes = int(manifest["size_bytes"])
    chunk_size = int(manifest["chunk_size"])
    offset = chunk_index * chunk_size
    return min(chunk_size, size_bytes - offset)


def _uploaded_bytes(manifest: dict) -> int:
    received = manifest.get("received_chunks", {})
    return sum(int(size) for size in received.values())


def initiate_upload_session(
    db: Session,
    data: EvidenceChunkedUploadInitiate,
    settings: Settings | None = None,
) -> dict:
    settings = _settings(settings)
    case = db.get(Case, data.case_id)
    if case is None:
        raise NotFoundError("case not found")

    try:
        safe_filename = normalize_safe_filename(data.original_filename)
        validate_evidence_extension(safe_filename)
    except EvidenceValidationError as exc:
        raise ValidationError(str(exc)) from exc

    max_size_bytes = settings.evidence_max_upload_bytes
    if data.size_bytes > max_size_bytes:
        raise ValidationError("evidence file exceeds maximum upload size")

    configured_chunk_size = settings.evidence_upload_chunk_size_bytes
    chunk_size = data.chunk_size or configured_chunk_size
    if chunk_size <= 0:
        raise ValidationError("chunk size must be greater than zero")
    if chunk_size > configured_chunk_size:
        raise ValidationError("chunk size exceeds configured maximum")

    total_chunks = math.ceil(data.size_bytes / chunk_size)
    upload_id = str(uuid4())
    session_dir = _session_dir(upload_id, settings)
    session_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
    _evidence_temp_path(session_dir).touch(exist_ok=False)

    expires_at = None
    ttl_seconds = settings.evidence_upload_session_ttl_seconds
    if ttl_seconds > 0:
        expires_at = _utcnow() + timedelta(seconds=ttl_seconds)

    manifest = {
        "upload_id": upload_id,
        "case_id": str(data.case_id),
        "original_filename": safe_filename,
        "size_bytes": data.size_bytes,
        "chunk_size": chunk_size,
        "total_chunks": total_chunks,
        "received_chunks": {},
        "os_family": data.os_family.value,
        "os_version": data.os_version,
        "architecture": data.architecture,
        "kernel_version": data.kernel_version,
        "symbol_table": data.symbol_table,
        "acquisition_tool": data.acquisition_tool,
        "acquisition_time": _serialize_datetime(data.acquisition_time),
        "created_at": _serialize_datetime(_utcnow()),
        "expires_at": _serialize_datetime(expires_at),
    }
    _write_manifest(session_dir, manifest)
    return {
        "upload_id": upload_id,
        "chunk_size": chunk_size,
        "max_size_bytes": max_size_bytes,
        "total_chunks": total_chunks,
        "expires_at": expires_at,
    }


async def write_upload_chunk(
    upload_id: UUID | str,
    chunk_index: int,
    body_stream: AsyncIterator[bytes],
    settings: Settings | None = None,
) -> dict:
    settings = _settings(settings)
    session_dir, manifest = _load_manifest(upload_id, settings)
    total_chunks = int(manifest["total_chunks"])
    if chunk_index < 0 or chunk_index >= total_chunks:
        raise ValidationError("chunk index is outside the upload range")

    expected_size = _expected_chunk_size(manifest, chunk_index)
    if expected_size <= 0:
        raise ValidationError("chunk index is outside the upload range")

    chunk_temp_path = session_dir / f".chunk-{chunk_index}.upload"
    bytes_received = 0
    try:
        with chunk_temp_path.open("wb") as chunk_file:
            async for part in body_stream:
                if not part:
                    continue
                bytes_received += len(part)
                if bytes_received > expected_size:
                    raise ValidationError("chunk exceeds expected size")
                chunk_file.write(part)

        if bytes_received != expected_size:
            raise ValidationError("chunk size does not match expected range")

        offset = chunk_index * int(manifest["chunk_size"])
        evidence_temp_path = _evidence_temp_path(session_dir)
        mode = "r+b" if evidence_temp_path.exists() else "w+b"
        with evidence_temp_path.open(mode) as evidence_file, chunk_temp_path.open("rb") as chunk_file:
            evidence_file.seek(offset)
            shutil.copyfileobj(chunk_file, evidence_file, length=CHUNK_COPY_BUFFER_BYTES)
            evidence_file.flush()

        manifest.setdefault("received_chunks", {})[str(chunk_index)] = bytes_received
        _write_manifest(session_dir, manifest)
        return {
            "upload_id": _safe_upload_id(upload_id),
            "chunk_index": chunk_index,
            "received_chunks": len(manifest["received_chunks"]),
            "total_chunks": total_chunks,
            "uploaded_bytes": _uploaded_bytes(manifest),
        }
    finally:
        chunk_temp_path.unlink(missing_ok=True)


def complete_upload_session(
    db: Session,
    storage_client: ObjectStorageClient,
    upload_id: UUID | str,
    settings: Settings | None = None,
) -> Evidence:
    settings = _settings(settings)
    session_dir, manifest = _load_manifest(upload_id, settings)
    received_chunks = manifest.get("received_chunks", {})
    total_chunks = int(manifest["total_chunks"])
    missing_chunks = [index for index in range(total_chunks) if str(index) not in received_chunks]
    if missing_chunks:
        raise ValidationError("upload is missing chunks")

    for index in range(total_chunks):
        expected_size = _expected_chunk_size(manifest, index)
        if int(received_chunks[str(index)]) != expected_size:
            raise ValidationError("upload session chunk manifest is invalid")

    evidence_temp_path = _evidence_temp_path(session_dir)
    if not evidence_temp_path.is_file():
        raise ValidationError("upload session file is missing")
    if evidence_temp_path.stat().st_size != int(manifest["size_bytes"]):
        raise ValidationError("upload size does not match the declared size")

    case_id = UUID(manifest["case_id"])
    case = db.get(Case, case_id)
    if case is None:
        raise NotFoundError("case not found")

    evidence = Evidence(
        case_id=case.id,
        source_type=EvidenceSourceType.UPLOAD.value,
        original_filename=manifest["original_filename"],
        content_type=CHUNK_CONTENT_TYPE,
        os_family=manifest.get("os_family") or "unknown",
        os_version=manifest.get("os_version"),
        architecture=manifest.get("architecture"),
        kernel_version=manifest.get("kernel_version"),
        symbol_table=manifest.get("symbol_table"),
        acquisition_tool=manifest.get("acquisition_tool"),
        acquisition_time=_parse_datetime(manifest.get("acquisition_time")),
    )
    db.add(evidence)
    db.flush()

    try:
        storage_client.ensure_buckets()
        upload_result = storage_client.upload_evidence(case.id, evidence.id, evidence_temp_path, manifest["original_filename"])
        evidence.original_filename = upload_result.safe_filename
        evidence.size_bytes = upload_result.hashes.size_bytes
        evidence.md5 = upload_result.hashes.md5
        evidence.sha256 = upload_result.hashes.sha256
        evidence.storage_bucket = upload_result.storage_object.bucket
        evidence.storage_key = upload_result.storage_object.key
        db.commit()
        db.refresh(evidence)
        shutil.rmtree(session_dir, ignore_errors=True)
        return evidence
    except EvidenceValidationError as exc:
        db.rollback()
        raise ValidationError(str(exc)) from exc
    except Exception:
        db.rollback()
        raise


def cancel_upload_session(upload_id: UUID | str, settings: Settings | None = None) -> None:
    settings = _settings(settings)
    session_dir = _session_dir(upload_id, settings)
    if not session_dir.exists():
        raise NotFoundError("upload session not found")
    shutil.rmtree(session_dir, ignore_errors=True)
