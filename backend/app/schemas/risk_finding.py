# Risk finding response schemas.

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from app.schemas.common import OrmModel


class RiskFindingRead(OrmModel):
    id: UUID
    analysis_job_id: UUID
    evidence_id: UUID
    plugin_result_id: UUID | None
    os_family: str
    os_scope: str
    source_plugin: str | None
    rule_id: str | None
    rule_name: str | None
    category: str | None
    severity: str
    score: int
    title: str
    description: str | None
    artifact_type: str | None
    artifact_id: str | None
    recommendation: str | None
    extra_data: dict | None
    created_at: datetime
    updated_at: datetime


class RiskFindingListResponse(BaseModel):
    items: list[RiskFindingRead]
