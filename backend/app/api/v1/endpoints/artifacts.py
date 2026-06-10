# Normalized artifact drill-down endpoints.

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.schemas.artifact import (
    CommandArtifactListResponse,
    MemoryRegionArtifactListResponse,
    ModuleArtifactListResponse,
    NetworkArtifactListResponse,
    ProcessArtifactListResponse,
    YaraMatchListResponse,
)
from app.services import artifact_service
from app.services.errors import NotFoundError

router = APIRouter()


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
