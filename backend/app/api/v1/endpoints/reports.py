# Report metadata endpoints.

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.api.v1.endpoints.download_utils import storage_download_response
from app.core.config import get_settings
from app.schemas.report import ReportListResponse, ReportRead
from app.services import download_service
from app.services import report_service
from app.services.errors import NotFoundError, ValidationError
from app.storage.client import ObjectStorageClient, get_storage_client

router = APIRouter()


@router.get("", response_model=ReportListResponse)
def list_reports(
    case_id: UUID | None = None,
    job_id: UUID | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    return {"items": report_service.list_reports(db, case_id=case_id, job_id=job_id, limit=limit, offset=offset)}


@router.get("/{report_id}", response_model=ReportRead)
def get_report(report_id: UUID, db: Session = Depends(get_db)):
    try:
        return report_service.get_report(db, report_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("/{report_id}/download", response_class=StreamingResponse)
def download_report(
    report_id: UUID,
    db: Session = Depends(get_db),
    storage_client: ObjectStorageClient = Depends(get_storage_client),
):
    try:
        report = report_service.get_report(db, report_id)
        spec = download_service.report_download_spec(report, get_settings())
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return storage_download_response(spec, storage_client)
