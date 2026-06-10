# Risk finding response schemas.

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

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
    effective_severity: str
    review_status: str = "new"
    analyst_verdict: str | None = None
    severity_override: str | None = None
    reviewed_at: datetime | None = None
    reviewed_by_name: str | None = None
    review_updated_at: datetime | None = None
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
    total: int | None = None
    limit: int | None = None
    offset: int | None = None


class RiskFindingReviewUpdate(BaseModel):
    review_status: str | None = None
    analyst_verdict: str | None = None
    severity_override: str | None = None
    reviewed_by_name: str | None = Field(default=None, max_length=255)
    note: str | None = Field(default=None, max_length=4000)

    @field_validator("review_status", "analyst_verdict", "severity_override", "reviewed_by_name", "note", mode="before")
    @classmethod
    def normalize_blank_string(cls, value: object) -> object:
        if isinstance(value, str):
            stripped = value.strip()
            return stripped or None
        return value
