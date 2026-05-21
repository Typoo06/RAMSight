"""Report response schemas."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from app.schemas.common import OrmModel


class ReportRead(OrmModel):
    id: UUID
    case_id: UUID
    evidence_id: UUID
    analysis_job_id: UUID
    os_family: str
    report_type: str
    format: str
    storage_bucket: str | None
    storage_key: str | None
    generated_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ReportListResponse(BaseModel):
    items: list[ReportRead]
