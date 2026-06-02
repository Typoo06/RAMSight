# Analysis job endpoints.

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.api.v1.endpoints.download_utils import storage_download_response
from app.core.config import get_settings
from app.schemas.analysis_job import AnalysisJobCreate, AnalysisJobListResponse, AnalysisJobRead, AnalysisJobStatusRead
from app.services import analysis_job_service, download_service
from app.services.errors import NotFoundError, ServiceUnavailableError, ValidationError
from app.services.job_dispatcher import AnalysisJobDispatcher, get_analysis_job_dispatcher
from app.storage.client import ObjectStorageClient, get_storage_client

router = APIRouter()


@router.post("", response_model=AnalysisJobRead, status_code=status.HTTP_201_CREATED)
def create_analysis_job(
    payload: AnalysisJobCreate,
    db: Session = Depends(get_db),
    dispatcher: AnalysisJobDispatcher = Depends(get_analysis_job_dispatcher),
):
    try:
        return analysis_job_service.create_analysis_job(db, payload, dispatcher)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except ServiceUnavailableError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc


@router.get("", response_model=AnalysisJobListResponse)
def list_analysis_jobs(
    case_id: UUID | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    return {"items": analysis_job_service.list_analysis_jobs(db, case_id=case_id, limit=limit, offset=offset)}


@router.get("/{job_id}", response_model=AnalysisJobRead)
def get_analysis_job(job_id: UUID, db: Session = Depends(get_db)):
    try:
        return analysis_job_service.get_analysis_job(db, job_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("/{job_id}/status", response_model=AnalysisJobStatusRead)
def get_analysis_job_status(job_id: UUID, db: Session = Depends(get_db)):
    try:
        return analysis_job_service.get_analysis_job(db, job_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


def download_ioc_export(
    job_id: UUID,
    export_format: str,
    db: Session,
    storage_client: ObjectStorageClient,
) -> StreamingResponse:
    try:
        job = analysis_job_service.get_analysis_job(db, job_id)
        spec = download_service.ioc_export_download_spec(job, export_format, get_settings())
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return storage_download_response(spec, storage_client)


@router.get("/{job_id}/iocs/export.json", response_class=StreamingResponse)
def download_ioc_json_export(
    job_id: UUID,
    db: Session = Depends(get_db),
    storage_client: ObjectStorageClient = Depends(get_storage_client),
):
    return download_ioc_export(job_id, "json", db, storage_client)


@router.get("/{job_id}/iocs/export.csv", response_class=StreamingResponse)
def download_ioc_csv_export(
    job_id: UUID,
    db: Session = Depends(get_db),
    storage_client: ObjectStorageClient = Depends(get_storage_client),
):
    return download_ioc_export(job_id, "csv", db, storage_client)


@router.get("/{job_id}/iocs/export.{export_format}", response_class=StreamingResponse)
def download_ioc_export_by_format(
    job_id: UUID,
    export_format: str,
    db: Session = Depends(get_db),
    storage_client: ObjectStorageClient = Depends(get_storage_client),
):
    return download_ioc_export(job_id, export_format, db, storage_client)
