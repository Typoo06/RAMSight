# Evidence request and response schemas.

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.common import EvidenceSourceType, OSFamily, OrmModel


class EvidenceRegister(BaseModel):
    case_id: UUID
    source_type: EvidenceSourceType
    original_filename: str = Field(min_length=1, max_length=255)
    content_type: str | None = None
    size_bytes: int | None = Field(default=None, ge=0)
    md5: str | None = Field(default=None, max_length=32)
    sha256: str | None = Field(default=None, max_length=64)
    storage_bucket: str | None = Field(default=None, max_length=255)
    storage_key: str | None = Field(default=None, max_length=1024)
    local_path: str | None = Field(default=None, max_length=1024)
    os_family: OSFamily = OSFamily.UNKNOWN
    os_version: str | None = None
    architecture: str | None = None
    kernel_version: str | None = None
    symbol_table: str | None = None
    acquisition_tool: str | None = None
    acquisition_time: datetime | None = None


class EvidenceChunkedUploadInitiate(BaseModel):
    case_id: UUID
    original_filename: str = Field(min_length=1, max_length=255)
    size_bytes: int = Field(gt=0)
    os_family: OSFamily = OSFamily.UNKNOWN
    os_version: str | None = None
    architecture: str | None = None
    kernel_version: str | None = None
    symbol_table: str | None = None
    acquisition_tool: str | None = None
    acquisition_time: datetime | None = None
    chunk_size: int | None = Field(default=None, gt=0)


class EvidenceChunkedUploadInitiateResponse(BaseModel):
    upload_id: UUID
    chunk_size: int
    max_size_bytes: int
    total_chunks: int
    expires_at: datetime | None = None


class EvidenceChunkUploadResponse(BaseModel):
    upload_id: UUID
    chunk_index: int
    received_chunks: int
    total_chunks: int
    uploaded_bytes: int


class EvidenceMultipartUploadInitiate(BaseModel):
    case_id: UUID
    filename: str = Field(min_length=1, max_length=255)
    size_bytes: int = Field(gt=0)
    content_type: str | None = Field(default=None, max_length=255)
    os_family: OSFamily = OSFamily.UNKNOWN
    os_version: str | None = None
    architecture: str | None = None
    kernel_version: str | None = None
    symbol_table: str | None = None
    acquisition_tool: str | None = None
    acquisition_time: datetime | None = None
    description: str | None = Field(default=None, max_length=1024)


class EvidenceMultipartUploadInitiateResponse(BaseModel):
    upload_session_id: UUID
    object_key: str
    recommended_part_size_bytes: int
    expected_part_count: int
    max_size_bytes: int
    expires_at: datetime | None = None


class EvidenceMultipartPresignPartRequest(BaseModel):
    part_number: int = Field(ge=1)


class EvidenceMultipartPresignPartResponse(BaseModel):
    part_number: int
    upload_url: str
    expires_at: datetime | None = None


class EvidenceMultipartPartComplete(BaseModel):
    part_number: int = Field(ge=1)
    etag: str = Field(min_length=1, max_length=256)
    size_bytes: int | None = Field(default=None, ge=0)


class EvidenceMultipartPartCompleteResponse(BaseModel):
    upload_session_id: UUID
    part_number: int
    completed_parts: int
    expected_part_count: int
    uploaded_bytes: int


class EvidenceRead(OrmModel):
    id: UUID
    case_id: UUID
    uploaded_by_id: UUID | None
    source_type: str
    original_filename: str
    content_type: str | None
    size_bytes: int | None
    md5: str | None
    sha256: str | None
    storage_bucket: str | None
    storage_key: str | None
    local_path: str | None
    os_family: str
    os_version: str | None
    architecture: str | None
    kernel_version: str | None
    symbol_table: str | None
    acquisition_tool: str | None
    acquisition_time: datetime | None
    created_at: datetime
    updated_at: datetime


class EvidenceListResponse(BaseModel):
    items: list[EvidenceRead]
