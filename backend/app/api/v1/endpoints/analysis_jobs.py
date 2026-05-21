"""Analysis job endpoints."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.schemas.analysis_job import AnalysisJobCreate, AnalysisJobListResponse, AnalysisJobRead, AnalysisJobStatusRead
from app.services import analysis_job_service
from app.services.errors import NotFoundError, ValidationError
from app.services.job_dispatcher import AnalysisJobDispatcher, get_analysis_job_dispatcher

router = APIRouter()


@router.post("", response_model=AnalysisJobRead, status_code=status.HTTP_201_CREATED)
def create_analysis_job(
    payload: AnalysisJobCreate,
    db: Session = Depends(get_db),
    dispatcher: AnalysisJobDispatcher = Depends(get_analysis_job_dispatcher),
):
    """Create a queued analysis job without running analysis in the API process."""
    try:
        return analysis_job_service.create_analysis_job(db, payload, dispatcher)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get("", response_model=AnalysisJobListResponse)
def list_analysis_jobs(
    case_id: UUID | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    """List analysis jobs."""
    return {"items": analysis_job_service.list_analysis_jobs(db, case_id=case_id, limit=limit, offset=offset)}


@router.get("/{job_id}", response_model=AnalysisJobRead)
def get_analysis_job(job_id: UUID, db: Session = Depends(get_db)):
    """Get one analysis job."""
    try:
        return analysis_job_service.get_analysis_job(db, job_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("/{job_id}/status", response_model=AnalysisJobStatusRead)
def get_analysis_job_status(job_id: UUID, db: Session = Depends(get_db)):
    """Get analysis job status."""
    try:
        return analysis_job_service.get_analysis_job(db, job_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
