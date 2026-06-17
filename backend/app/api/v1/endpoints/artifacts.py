# Normalized artifact drill-down endpoints.

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.api.v1.endpoints.download_utils import generated_export_response
from app.schemas.artifact import (
    CommandArtifactListResponse,
    MemoryRegionArtifactListResponse,
    ModuleArtifactListResponse,
    NetworkArtifactListResponse,
    ProcessArtifactListResponse,
    YaraMatchListResponse,
)
from app.services import artifact_service
from app.services.result_export_service import build_export_file, export_rows
from app.services.errors import NotFoundError

router = APIRouter()

PROCESS_ARTIFACT_EXPORT_FIELDS = [
    "id", "analysis_job_id", "evidence_id", "plugin_result_id", "os_family", "source_plugin",
    "pid", "ppid", "name", "image_path", "command_line", "user_name", "session_id",
    "created_time", "exited_time", "is_hidden_candidate", "created_at",
]
NETWORK_ARTIFACT_EXPORT_FIELDS = [
    "id", "analysis_job_id", "evidence_id", "plugin_result_id", "os_family", "source_plugin",
    "protocol", "local_address", "local_port", "remote_address", "remote_port", "state",
    "pid", "process_name", "created_time", "created_at",
]
MODULE_ARTIFACT_EXPORT_FIELDS = [
    "id", "analysis_job_id", "evidence_id", "plugin_result_id", "os_family", "source_plugin",
    "pid", "process_name", "module_name", "module_path", "base_address", "size_bytes", "load_time", "created_at",
]
MEMORY_REGION_ARTIFACT_EXPORT_FIELDS = [
    "id", "analysis_job_id", "evidence_id", "plugin_result_id", "os_family", "source_plugin",
    "pid", "process_name", "start_address", "end_address", "protection", "is_executable",
    "is_private", "description", "hexdump_excerpt", "disassembly_excerpt", "created_at",
]
YARA_MATCH_EXPORT_FIELDS = [
    "id", "analysis_job_id", "evidence_id", "plugin_result_id", "os_family", "source_plugin",
    "rule_name", "namespace", "tags", "target_type", "target_identifier", "offset",
    "matched_text_excerpt", "extra_data", "created_at",
]


def pagination_limit(default: int = 100):
    return Query(default=default, ge=1, le=500)


def pagination_offset():
    return Query(default=0, ge=0)


@router.get("/analysis-jobs/{job_id}/artifacts/processes", response_model=ProcessArtifactListResponse)
def list_process_artifacts(
    job_id: UUID,
    pid: int | None = None,
    process_name: str | None = None,
    source_plugin: str | None = None,
    limit: int = pagination_limit(),
    offset: int = pagination_offset(),
    db: Session = Depends(get_db),
):
    try:
        items = artifact_service.list_process_artifacts(db, job_id, pid, process_name, source_plugin, limit, offset)
        total = artifact_service.count_process_artifacts(db, job_id, pid, process_name, source_plugin)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/analysis-jobs/{job_id}/artifacts/commands", response_model=CommandArtifactListResponse)
def list_command_artifacts(
    job_id: UUID,
    pid: int | None = None,
    process_name: str | None = None,
    source_plugin: str | None = None,
    limit: int = pagination_limit(),
    offset: int = pagination_offset(),
    db: Session = Depends(get_db),
):
    try:
        items = artifact_service.list_command_artifacts(db, job_id, pid, process_name, source_plugin, limit, offset)
        total = artifact_service.count_command_artifacts(db, job_id, pid, process_name, source_plugin)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/analysis-jobs/{job_id}/artifacts/network", response_model=NetworkArtifactListResponse)
def list_network_artifacts(
    job_id: UUID,
    pid: int | None = None,
    process_name: str | None = None,
    source_plugin: str | None = None,
    remote_address: str | None = None,
    protocol: str | None = None,
    limit: int = pagination_limit(),
    offset: int = pagination_offset(),
    db: Session = Depends(get_db),
):
    try:
        items = artifact_service.list_network_artifacts(
            db, job_id, pid, process_name, source_plugin, remote_address, protocol, limit, offset
        )
        total = artifact_service.count_network_artifacts(
            db, job_id, pid, process_name, source_plugin, remote_address, protocol
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/analysis-jobs/{job_id}/artifacts/modules", response_model=ModuleArtifactListResponse)
def list_module_artifacts(
    job_id: UUID,
    pid: int | None = None,
    process_name: str | None = None,
    source_plugin: str | None = None,
    limit: int = pagination_limit(),
    offset: int = pagination_offset(),
    db: Session = Depends(get_db),
):
    try:
        items = artifact_service.list_module_artifacts(db, job_id, pid, process_name, source_plugin, limit, offset)
        total = artifact_service.count_module_artifacts(db, job_id, pid, process_name, source_plugin)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/analysis-jobs/{job_id}/artifacts/memory-regions", response_model=MemoryRegionArtifactListResponse)
def list_memory_region_artifacts(
    job_id: UUID,
    pid: int | None = None,
    process_name: str | None = None,
    source_plugin: str | None = None,
    executable_only: bool | None = None,
    suspicious_only: bool | None = None,
    limit: int = pagination_limit(),
    offset: int = pagination_offset(),
    db: Session = Depends(get_db),
):
    try:
        items = artifact_service.list_memory_region_artifacts(
            db, job_id, pid, process_name, source_plugin, executable_only, suspicious_only, limit, offset
        )
        total = artifact_service.count_memory_region_artifacts(
            db, job_id, pid, process_name, source_plugin, executable_only, suspicious_only
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/analysis-jobs/{job_id}/artifacts/yara-matches", response_model=YaraMatchListResponse)
def list_yara_matches(
    job_id: UUID,
    pid: int | None = None,
    source_plugin: str | None = None,
    rule_name: str | None = None,
    target_identifier: str | None = None,
    limit: int = pagination_limit(),
    offset: int = pagination_offset(),
    db: Session = Depends(get_db),
):
    try:
        items = artifact_service.list_yara_matches(
            db, job_id, pid, source_plugin, rule_name, target_identifier, limit, offset
        )
        total = artifact_service.count_yara_matches(db, job_id, pid, source_plugin, rule_name, target_identifier)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"items": items, "total": total, "limit": limit, "offset": offset}


def artifact_export_response(filename_base: str, kind: str, items: list[object], fields: list[str], export_format: str):
    rows = export_rows(items, fields)
    return generated_export_response(build_export_file(filename_base, kind, rows, export_format))


@router.get("/analysis-jobs/{job_id}/artifacts/processes/export.{export_format}", response_class=Response)
def export_process_artifacts(
    job_id: UUID,
    export_format: str,
    pid: int | None = None,
    process_name: str | None = None,
    source_plugin: str | None = None,
    db: Session = Depends(get_db),
):
    try:
        items = artifact_service.export_process_artifacts(db, job_id, pid, process_name, source_plugin)
        return artifact_export_response("process_artifacts", "process_artifacts", items, PROCESS_ARTIFACT_EXPORT_FIELDS, export_format)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get("/analysis-jobs/{job_id}/artifacts/network/export.{export_format}", response_class=Response)
def export_network_artifacts(
    job_id: UUID,
    export_format: str,
    pid: int | None = None,
    process_name: str | None = None,
    source_plugin: str | None = None,
    remote_address: str | None = None,
    protocol: str | None = None,
    db: Session = Depends(get_db),
):
    try:
        items = artifact_service.export_network_artifacts(
            db, job_id, pid, process_name, source_plugin, remote_address, protocol
        )
        return artifact_export_response("network_artifacts", "network_artifacts", items, NETWORK_ARTIFACT_EXPORT_FIELDS, export_format)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get("/analysis-jobs/{job_id}/artifacts/modules/export.{export_format}", response_class=Response)
def export_module_artifacts(
    job_id: UUID,
    export_format: str,
    pid: int | None = None,
    process_name: str | None = None,
    source_plugin: str | None = None,
    db: Session = Depends(get_db),
):
    try:
        items = artifact_service.export_module_artifacts(db, job_id, pid, process_name, source_plugin)
        return artifact_export_response("module_artifacts", "module_artifacts", items, MODULE_ARTIFACT_EXPORT_FIELDS, export_format)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get("/analysis-jobs/{job_id}/artifacts/memory-regions/export.{export_format}", response_class=Response)
def export_memory_region_artifacts(
    job_id: UUID,
    export_format: str,
    pid: int | None = None,
    process_name: str | None = None,
    source_plugin: str | None = None,
    executable_only: bool | None = None,
    suspicious_only: bool | None = None,
    db: Session = Depends(get_db),
):
    try:
        items = artifact_service.export_memory_region_artifacts(
            db, job_id, pid, process_name, source_plugin, executable_only, suspicious_only
        )
        return artifact_export_response(
            "memory_region_artifacts", "memory_region_artifacts", items, MEMORY_REGION_ARTIFACT_EXPORT_FIELDS, export_format
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get("/analysis-jobs/{job_id}/artifacts/yara-matches/export.{export_format}", response_class=Response)
def export_yara_matches(
    job_id: UUID,
    export_format: str,
    pid: int | None = None,
    source_plugin: str | None = None,
    rule_name: str | None = None,
    target_identifier: str | None = None,
    db: Session = Depends(get_db),
):
    try:
        items = artifact_service.export_yara_matches(db, job_id, pid, source_plugin, rule_name, target_identifier)
        return artifact_export_response("yara_matches", "yara_matches", items, YARA_MATCH_EXPORT_FIELDS, export_format)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
