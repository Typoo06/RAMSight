"""IOC response schemas."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from app.schemas.common import OrmModel


class IOCRead(OrmModel):
    id: UUID
    analysis_job_id: UUID
    evidence_id: UUID
    risk_finding_id: UUID | None
    os_family: str
    source_plugin: str | None
    ioc_type: str
    value: str
    normalized_value: str | None
    context: str | None
    confidence: int | None
    extra_data: dict | None
    created_at: datetime
    updated_at: datetime


class IOCListResponse(BaseModel):
    items: list[IOCRead]
