# Analyst note request and response schemas.

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from app.schemas.common import OrmModel


class AnalystNoteRead(OrmModel):
    id: UUID
    case_id: UUID
    evidence_id: UUID | None
    analysis_job_id: UUID | None
    risk_finding_id: UUID | None
    note_type: str
    author_name: str | None
    content: str
    created_at: datetime
    updated_at: datetime


class AnalystNoteCreate(BaseModel):
    content: str = Field(max_length=4000)
    author_name: str | None = Field(default=None, max_length=255)
    note_type: str | None = Field(default="finding_review", max_length=50)

    @field_validator("content", "author_name", "note_type", mode="before")
    @classmethod
    def normalize_string(cls, value: object) -> object:
        if isinstance(value, str):
            stripped = value.strip()
            return stripped or None
        return value


class AnalystNoteListResponse(BaseModel):
    items: list[AnalystNoteRead]
