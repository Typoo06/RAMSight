"""Evidence endpoints."""

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.schemas.common import OSFamily
from app.schemas.evidence import EvidenceListResponse, EvidenceRead, EvidenceRegister
from app.services import evidence_service
from app.services.errors import NotFoundError, ValidationError
from app.storage.client import ObjectStorageClient, get_storage_client

router = APIRouter()


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
    """Upload evidence to object storage and store metadata only."""
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
    """Register existing evidence object/path metadata without uploading content."""
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
    """List evidence metadata."""
    return {"items": evidence_service.list_evidences(db, case_id=case_id, limit=limit, offset=offset)}


@router.get("/{evidence_id}", response_model=EvidenceRead)
def get_evidence(evidence_id: UUID, db: Session = Depends(get_db)):
    """Get one evidence metadata record."""
    try:
        return evidence_service.get_evidence(db, evidence_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
