# Risk finding endpoints.

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.schemas.analyst_note import AnalystNoteCreate, AnalystNoteListResponse, AnalystNoteRead
from app.schemas.risk_finding import RiskFindingListResponse, RiskFindingRead, RiskFindingReviewUpdate
from app.services import analyst_note_service, risk_finding_service
from app.services.errors import NotFoundError, ValidationError

router = APIRouter()


@router.get("", response_model=RiskFindingListResponse)
def list_risk_findings(
    case_id: UUID | None = None,
    job_id: UUID | None = None,
    review_status: str | None = None,
    analyst_verdict: str | None = None,
    severity_effective: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    try:
        items = risk_finding_service.list_risk_findings(
            db,
            case_id=case_id,
            job_id=job_id,
            review_status=review_status,
            analyst_verdict=analyst_verdict,
            severity_effective=severity_effective,
            limit=limit,
            offset=offset,
        )
        total = risk_finding_service.count_risk_findings(
            db,
            case_id=case_id,
            job_id=job_id,
            review_status=review_status,
            analyst_verdict=analyst_verdict,
            severity_effective=severity_effective,
        )
        return {
            "items": items,
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.patch("/{finding_id}/review", response_model=RiskFindingRead)
def update_risk_finding_review(
    finding_id: UUID,
    data: RiskFindingReviewUpdate,
    db: Session = Depends(get_db),
):
    try:
        return risk_finding_service.update_review(db, finding_id=finding_id, data=data)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get("/{finding_id}/notes", response_model=AnalystNoteListResponse)
def list_risk_finding_notes(
    finding_id: UUID,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    try:
        return {"items": analyst_note_service.list_finding_notes(db, finding_id=finding_id, limit=limit, offset=offset)}
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.post("/{finding_id}/notes", response_model=AnalystNoteRead, status_code=status.HTTP_201_CREATED)
def create_risk_finding_note(
    finding_id: UUID,
    data: AnalystNoteCreate,
    db: Session = Depends(get_db),
):
    try:
        return analyst_note_service.create_finding_note(
            db,
            finding_id=finding_id,
            content=data.content,
            author_name=data.author_name,
            note_type=data.note_type,
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
