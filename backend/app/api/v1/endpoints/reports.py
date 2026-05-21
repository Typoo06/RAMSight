"""Report metadata endpoints."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.schemas.report import ReportListResponse, ReportRead
from app.services import report_service
from app.services.errors import NotFoundError

router = APIRouter()


@router.get("", response_model=ReportListResponse)
def list_reports(
    case_id: UUID | None = None,
    job_id: UUID | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    """List generated report metadata."""
    return {"items": report_service.list_reports(db, case_id=case_id, job_id=job_id, limit=limit, offset=offset)}


@router.get("/{report_id}", response_model=ReportRead)
def get_report(report_id: UUID, db: Session = Depends(get_db)):
    """Get one report metadata record."""
    try:
        return report_service.get_report(db, report_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
