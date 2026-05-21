"""Risk finding endpoints."""

from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.schemas.risk_finding import RiskFindingListResponse
from app.services import risk_finding_service

router = APIRouter()


@router.get("", response_model=RiskFindingListResponse)
def list_risk_findings(
    case_id: UUID | None = None,
    job_id: UUID | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    """List risk findings by optional case/job filters."""
    return {
        "items": risk_finding_service.list_risk_findings(
            db, case_id=case_id, job_id=job_id, limit=limit, offset=offset
        )
    }
