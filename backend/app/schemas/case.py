"""Case request and response schemas."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.common import OrmModel


class CaseCreate(BaseModel):
    case_code: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    status: str = Field(default="open", max_length=50)


class CaseRead(OrmModel):
    id: UUID
    case_code: str
    name: str
    description: str | None
    status: str
    created_by_id: UUID | None
    created_at: datetime
    updated_at: datetime


class CaseListResponse(BaseModel):
    items: list[CaseRead]
