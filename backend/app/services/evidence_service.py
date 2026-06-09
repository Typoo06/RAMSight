# Evidence service functions.

from pathlib import Path
import shutil
import tempfile
from uuid import UUID

from fastapi import UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Case, Evidence
from app.models.enums import EvidenceSourceType
from app.core.config import get_settings
from app.schemas.common import OSFamily
from app.schemas.evidence import EvidenceRegister
from app.services.errors import NotFoundError, ValidationError
from app.storage.client import ObjectStorageClient
from app.storage.validation import EvidenceValidationError, normalize_safe_filename, validate_evidence_extension


DIRECT_UPLOAD_COPY_CHUNK_SIZE = 1024 * 1024


def _copy_upload_to_temp(upload_file: UploadFile, max_size_bytes: int) -> Path:
    suffix = Path(upload_file.filename or "evidence.raw").suffix
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
        total_bytes = 0
        while True:
            chunk = upload_file.file.read(DIRECT_UPLOAD_COPY_CHUNK_SIZE)
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > max_size_bytes:
                temp_path = Path(temp_file.name)
                temp_file.close()
                temp_path.unlink(missing_ok=True)
                raise EvidenceValidationError(
                    "direct evidence upload exceeds maximum size; use browser chunked upload for large memory dumps"
                )
            temp_file.write(chunk)
        return Path(temp_file.name)


def upload_evidence(
    db: Session,
    storage_client: ObjectStorageClient,
    upload_file: UploadFile,
    case_id: UUID,
    os_family: str = OSFamily.UNKNOWN.value,
    os_version: str | None = None,
    architecture: str | None = None,
    kernel_version: str | None = None,
    symbol_table: str | None = None,
    acquisition_tool: str | None = None,
    acquisition_time=None,
) -> Evidence:
    case = db.get(Case, case_id)
    if case is None:
        raise NotFoundError("case not found")

    original_filename = upload_file.filename or "evidence.raw"
    settings = get_settings()
    direct_upload_max_bytes = min(settings.evidence_direct_upload_max_bytes, settings.evidence_max_upload_bytes)
    try:
        safe_filename = normalize_safe_filename(original_filename)
        validate_evidence_extension(safe_filename)
        temp_path = _copy_upload_to_temp(upload_file, direct_upload_max_bytes)
    except EvidenceValidationError as exc:
        raise ValidationError(str(exc)) from exc

    try:
        evidence = Evidence(
            case_id=case_id,
            # TODO: connect uploaded_by_id when authentication/current_user exists.
            source_type=EvidenceSourceType.UPLOAD.value,
            original_filename=original_filename,
            content_type=upload_file.content_type,
            os_family=os_family,
            os_version=os_version,
            architecture=architecture,
            kernel_version=kernel_version,
            symbol_table=symbol_table,
            acquisition_tool=acquisition_tool,
            acquisition_time=acquisition_time,
        )
        db.add(evidence)
        db.flush()

        storage_client.ensure_buckets()
        upload_result = storage_client.upload_evidence(case_id, evidence.id, temp_path, original_filename)

        evidence.original_filename = upload_result.safe_filename
        evidence.size_bytes = upload_result.hashes.size_bytes
        evidence.md5 = upload_result.hashes.md5
        evidence.sha256 = upload_result.hashes.sha256
        evidence.storage_bucket = upload_result.storage_object.bucket
        evidence.storage_key = upload_result.storage_object.key
        db.commit()
        db.refresh(evidence)
        return evidence
    except EvidenceValidationError as exc:
        db.rollback()
        raise ValidationError(str(exc)) from exc
    finally:
        temp_path.unlink(missing_ok=True)


def register_evidence(db: Session, data: EvidenceRegister) -> Evidence:
    case = db.get(Case, data.case_id)
    if case is None:
        raise NotFoundError("case not found")
    if data.source_type == EvidenceSourceType.UPLOAD.value:
        raise ValidationError("register endpoint cannot use source_type=upload")
    if data.source_type == EvidenceSourceType.LOCAL_PATH.value:
        raise ValidationError("local_path evidence registration is disabled for the demo workflow; use upload or minio_object")
    if data.source_type == EvidenceSourceType.MINIO_OBJECT.value and (not data.storage_bucket or not data.storage_key):
        raise ValidationError("minio_object evidence requires storage_bucket and storage_key")

    evidence = Evidence(**data.model_dump())
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    return evidence


def list_evidences(db: Session, case_id: UUID | None = None, limit: int = 100, offset: int = 0) -> list[Evidence]:
    statement = select(Evidence).order_by(Evidence.created_at.desc()).offset(offset).limit(limit)
    if case_id is not None:
        statement = statement.where(Evidence.case_id == case_id)
    return list(db.execute(statement).scalars())


def get_evidence(db: Session, evidence_id: UUID) -> Evidence:
    evidence = db.get(Evidence, evidence_id)
    if evidence is None:
        raise NotFoundError("evidence not found")
    return evidence
