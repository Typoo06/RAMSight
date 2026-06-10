# Evidence endpoints.

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, Path, Query, Request, UploadFile, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.schemas.common import OSFamily
from app.schemas.evidence import (
    EvidenceChunkUploadResponse,
    EvidenceChunkedUploadInitiate,
    EvidenceChunkedUploadInitiateResponse,
    EvidenceListResponse,
    EvidenceMultipartPartComplete,
    EvidenceMultipartPartCompleteResponse,
    EvidenceMultipartPresignPartRequest,
    EvidenceMultipartPresignPartResponse,
    EvidenceMultipartUploadInitiate,
    EvidenceMultipartUploadInitiateResponse,
    EvidenceRead,
    EvidenceRegister,
)
from app.services import evidence_multipart_upload_service, evidence_service, evidence_upload_session_service
from app.services.errors import NotFoundError, ValidationError
from app.storage.client import ObjectStorageClient, get_storage_client

router = APIRouter()


@router.post(
    "/multipart/initiate",
    response_model=EvidenceMultipartUploadInitiateResponse,
    status_code=status.HTTP_201_CREATED,
)
def initiate_multipart_evidence_upload(
    payload: EvidenceMultipartUploadInitiate,
    db: Session = Depends(get_db),
    storage_client: ObjectStorageClient = Depends(get_storage_client),
):
    try:
        return evidence_multipart_upload_service.initiate_multipart_upload(db, storage_client, payload)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="multipart evidence upload could not be initiated") from exc


@router.post(
    "/multipart/{session_id}/presign-part",
    response_model=EvidenceMultipartPresignPartResponse,
)
def presign_multipart_evidence_part(
    payload: EvidenceMultipartPresignPartRequest,
    session_id: UUID,
    storage_client: ObjectStorageClient = Depends(get_storage_client),
):
    try:
        return evidence_multipart_upload_service.presign_upload_part(storage_client, session_id, payload)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="multipart upload part URL could not be created") from exc


@router.post(
    "/multipart/{session_id}/parts",
    response_model=EvidenceMultipartPartCompleteResponse,
)
def record_multipart_evidence_part(
    payload: EvidenceMultipartPartComplete,
    session_id: UUID,
):
    try:
        return evidence_multipart_upload_service.record_completed_part(session_id, payload)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/multipart/{session_id}/complete", response_model=EvidenceRead, status_code=status.HTTP_201_CREATED)
def complete_multipart_evidence_upload(
    session_id: UUID,
    db: Session = Depends(get_db),
    storage_client: ObjectStorageClient = Depends(get_storage_client),
):
    try:
        return evidence_multipart_upload_service.complete_multipart_upload(db, storage_client, session_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="multipart evidence upload could not be completed") from exc


@router.delete("/multipart/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def cancel_multipart_evidence_upload(
    session_id: UUID,
    storage_client: ObjectStorageClient = Depends(get_storage_client),
):
    try:
        evidence_multipart_upload_service.abort_multipart_upload(storage_client, session_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="multipart evidence upload could not be cancelled") from exc
    return None


@router.post(
    "/uploads/initiate",
    response_model=EvidenceChunkedUploadInitiateResponse,
    status_code=status.HTTP_201_CREATED,
)
def initiate_chunked_evidence_upload(
    payload: EvidenceChunkedUploadInitiate,
    db: Session = Depends(get_db),
):
    try:
        return evidence_upload_session_service.initiate_upload_session(db, payload)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.put(
    "/uploads/{upload_id}/chunks/{chunk_index}",
    response_model=EvidenceChunkUploadResponse,
)
async def upload_evidence_chunk(
    request: Request,
    upload_id: UUID,
    chunk_index: int = Path(..., ge=0),
):
    content_type = (request.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
    if content_type != evidence_upload_session_service.CHUNK_CONTENT_TYPE:
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="chunk must use application/octet-stream")
    try:
        return await evidence_upload_session_service.write_upload_chunk(upload_id, chunk_index, request.stream())
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/uploads/{upload_id}/complete", response_model=EvidenceRead, status_code=status.HTTP_201_CREATED)
def complete_chunked_evidence_upload(
    upload_id: UUID,
    db: Session = Depends(get_db),
    storage_client: ObjectStorageClient = Depends(get_storage_client),
):
    try:
        return evidence_upload_session_service.complete_upload_session(db, storage_client, upload_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="evidence upload could not be completed") from exc


@router.delete("/uploads/{upload_id}", status_code=status.HTTP_204_NO_CONTENT)
def cancel_chunked_evidence_upload(upload_id: UUID):
    try:
        evidence_upload_session_service.cancel_upload_session(upload_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return None


@router.post("/upload", response_model=EvidenceRead, status_code=status.HTTP_201_CREATED)
def upload_evidence(
    case_id: UUID = Form(...),
    os_family: OSFamily = Form(OSFamily.UNKNOWN),
    os_version: str | None = Form(default=None),
    architecture: str | None = Form(default=None),
    kernel_version: str | None = Form(default=None),
    symbol_table: str | None = Form(default=None),
    acquisition_tool: str | None = Form(default=None),
    acquisition_time: datetime | None = Form(default=None),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    storage_client: ObjectStorageClient = Depends(get_storage_client),
):
    try:
        return evidence_service.upload_evidence(
            db=db,
            storage_client=storage_client,
            upload_file=file,
            case_id=case_id,
            os_family=os_family.value,
            os_version=os_version,
            architecture=architecture,
            kernel_version=kernel_version,
            symbol_table=symbol_table,
            acquisition_tool=acquisition_tool,
            acquisition_time=acquisition_time,
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/register", response_model=EvidenceRead, status_code=status.HTTP_201_CREATED)
def register_evidence(payload: EvidenceRegister, db: Session = Depends(get_db)):
    try:
        return evidence_service.register_evidence(db, payload)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get("", response_model=EvidenceListResponse)
def list_evidences(
    case_id: UUID | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    return {"items": evidence_service.list_evidences(db, case_id=case_id, limit=limit, offset=offset)}


@router.get("/{evidence_id}", response_model=EvidenceRead)
def get_evidence(evidence_id: UUID, db: Session = Depends(get_db)):
    try:
        return evidence_service.get_evidence(db, evidence_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
