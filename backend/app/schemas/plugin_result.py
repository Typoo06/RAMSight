# Plugin result response schemas.

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from app.schemas.common import OrmModel


class PluginResultRead(OrmModel):
    id: UUID
    analysis_job_id: UUID
    evidence_id: UUID
    os_family: str
    plugin_profile: str | None
    plugin_name: str
    source_plugin: str
    status: str
    raw_output_bucket: str | None
    raw_output_key: str | None
    parsed_output_bucket: str | None
    parsed_output_key: str | None
    parsed_record_count: int | None
    error_message: str | None
    duration_ms: int | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class PluginResultListResponse(BaseModel):
    items: list[PluginResultRead]
