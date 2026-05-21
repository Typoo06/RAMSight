# Shared API schemas and enum-like values.

from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class OSFamily(StrEnum):
    WINDOWS = "windows"
    LINUX = "linux"
    UNKNOWN = "unknown"


class EvidenceSourceType(StrEnum):
    UPLOAD = "upload"
    MINIO_OBJECT = "minio_object"
    LOCAL_PATH = "local_path"


class AnalysisJobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class OrmModel(BaseModel):

    model_config = ConfigDict(from_attributes=True)


class ListResponse(BaseModel):

    items: list


class CaseJobQuery(BaseModel):

    case_id: UUID | None = None
    job_id: UUID | None = None
    limit: int = Field(default=100, ge=1, le=500)
    offset: int = Field(default=0, ge=0)
