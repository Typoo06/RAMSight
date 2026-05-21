"""Analysis job request and response schemas."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.common import OSFamily, OrmModel


class AnalysisJobCreate(BaseModel):
    case_id: UUID
    evidence_id: UUID
    os_family: OSFamily = OSFamily.UNKNOWN
    os_version: str | None = None
    architecture: str | None = None
    kernel_version: str | None = None
    symbol_table: str | None = None
    plugin_profile: str | None = Field(default=None, max_length=100)
    requested_plugins: list[str] | None = None


class AnalysisJobRead(OrmModel):
    id: UUID
    case_id: UUID
    evidence_id: UUID
    created_by_id: UUID | None
    status: str
    os_family: str
    os_version: str | None
    architecture: str | None
    kernel_version: str | None
    symbol_table: str | None
    plugin_profile: str | None
    requested_plugins: list[str] | None
    error_message: str | None
    duration_ms: int | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class AnalysisJobStatusRead(OrmModel):
    id: UUID
    status: str
    error_message: str | None
    duration_ms: int | None
    started_at: datetime | None
    completed_at: datetime | None
    updated_at: datetime


class AnalysisJobListResponse(BaseModel):
    items: list[AnalysisJobRead]
