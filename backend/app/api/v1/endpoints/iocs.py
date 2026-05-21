# IOC endpoints.

from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.schemas.ioc import IOCListResponse
from app.services import ioc_service

router = APIRouter()


@router.get("", response_model=IOCListResponse)
def list_iocs(
    case_id: UUID | None = None,
    job_id: UUID | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    return {"items": ioc_service.list_iocs(db, case_id=case_id, job_id=job_id, limit=limit, offset=offset)}
