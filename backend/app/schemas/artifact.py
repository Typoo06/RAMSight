# Normalized artifact response schemas.

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from app.schemas.common import OrmModel


class ArtifactBaseRead(OrmModel):
    id: UUID
    analysis_job_id: UUID
    evidence_id: UUID
    plugin_result_id: UUID | None
    os_family: str
    source_plugin: str | None
    created_at: datetime


class ProcessArtifactRead(ArtifactBaseRead):
    pid: int | None
    ppid: int | None
    name: str | None
    image_path: str | None
    command_line: str | None
    user_name: str | None
    session_id: int | None
    created_time: datetime | None
    exited_time: datetime | None
    is_hidden_candidate: bool


class CommandArtifactRead(ArtifactBaseRead):
    pid: int | None
    process_name: str | None
    command: str | None
    shell_type: str | None
    user_name: str | None
    executed_at: datetime | None


class NetworkArtifactRead(ArtifactBaseRead):
    protocol: str | None
    local_address: str | None
    local_port: int | None
    remote_address: str | None
    remote_port: int | None
    state: str | None
    pid: int | None
    process_name: str | None
    created_time: datetime | None


class ModuleArtifactRead(ArtifactBaseRead):
    pid: int | None
    process_name: str | None
    module_name: str | None
    module_path: str | None
    base_address: str | None
    size_bytes: int | None
    load_time: datetime | None


class MemoryRegionArtifactRead(ArtifactBaseRead):
    pid: int | None
    process_name: str | None
    start_address: str | None
    end_address: str | None
    protection: str | None
    is_executable: bool
    is_private: bool
    description: str | None
    hexdump_excerpt: str | None
    disassembly_excerpt: str | None


class YaraMatchRead(OrmModel):
    id: UUID
    analysis_job_id: UUID
    evidence_id: UUID
    plugin_result_id: UUID | None
    os_family: str
    source_plugin: str | None
    rule_name: str
    namespace: str | None
    tags: list[str] | None
    target_type: str | None
    target_identifier: str | None
    offset: int | None
    matched_text_excerpt: str | None
    extra_data: dict | None
    created_at: datetime


class ProcessArtifactListResponse(BaseModel):
    items: list[ProcessArtifactRead]


class CommandArtifactListResponse(BaseModel):
    items: list[CommandArtifactRead]


class NetworkArtifactListResponse(BaseModel):
    items: list[NetworkArtifactRead]


class ModuleArtifactListResponse(BaseModel):
    items: list[ModuleArtifactRead]


class MemoryRegionArtifactListResponse(BaseModel):
    items: list[MemoryRegionArtifactRead]


class YaraMatchListResponse(BaseModel):
    items: list[YaraMatchRead]
