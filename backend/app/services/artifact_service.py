# Read-only normalized artifact query service.

from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models import (
    AnalysisJob,
    CommandArtifact,
    MemoryRegionArtifact,
    ModuleArtifact,
    NetworkArtifact,
    ProcessArtifact,
    YaraMatch,
)
from app.services.errors import NotFoundError


def validate_analysis_job(db: Session, job_id: UUID) -> AnalysisJob:
    job = db.get(AnalysisJob, job_id)
    if job is None:
        raise NotFoundError("analysis job not found")
    return job


def apply_common_filters(statement, model, job_id: UUID, pid: int | None, source_plugin: str | None):
    statement = statement.where(model.analysis_job_id == job_id)
    if pid is not None and hasattr(model, "pid"):
        statement = statement.where(model.pid == pid)
    if source_plugin:
        statement = statement.where(model.source_plugin == source_plugin)
    return statement


def list_process_artifacts(
    db: Session,
    job_id: UUID,
    pid: int | None = None,
    process_name: str | None = None,
    source_plugin: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[ProcessArtifact]:
    validate_analysis_job(db, job_id)
    statement = apply_common_filters(select(ProcessArtifact), ProcessArtifact, job_id, pid, source_plugin)
    if process_name:
        statement = statement.where(ProcessArtifact.name.ilike(f"%{process_name}%"))
    return list(db.execute(statement.order_by(ProcessArtifact.pid.asc()).offset(offset).limit(limit)).scalars())


def list_command_artifacts(
    db: Session,
    job_id: UUID,
    pid: int | None = None,
    process_name: str | None = None,
    source_plugin: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[CommandArtifact]:
    validate_analysis_job(db, job_id)
    statement = apply_common_filters(select(CommandArtifact), CommandArtifact, job_id, pid, source_plugin)
    if process_name:
        statement = statement.where(CommandArtifact.process_name.ilike(f"%{process_name}%"))
    return list(db.execute(statement.order_by(CommandArtifact.pid.asc()).offset(offset).limit(limit)).scalars())


def list_network_artifacts(
    db: Session,
    job_id: UUID,
    pid: int | None = None,
    process_name: str | None = None,
    source_plugin: str | None = None,
    remote_address: str | None = None,
    protocol: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[NetworkArtifact]:
    validate_analysis_job(db, job_id)
    statement = apply_common_filters(select(NetworkArtifact), NetworkArtifact, job_id, pid, source_plugin)
    if process_name:
        statement = statement.where(NetworkArtifact.process_name.ilike(f"%{process_name}%"))
    if remote_address:
        statement = statement.where(NetworkArtifact.remote_address == remote_address)
    if protocol:
        statement = statement.where(NetworkArtifact.protocol == protocol)
    return list(db.execute(statement.order_by(NetworkArtifact.pid.asc()).offset(offset).limit(limit)).scalars())


def list_module_artifacts(
    db: Session,
    job_id: UUID,
    pid: int | None = None,
    process_name: str | None = None,
    source_plugin: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[ModuleArtifact]:
    validate_analysis_job(db, job_id)
    statement = apply_common_filters(select(ModuleArtifact), ModuleArtifact, job_id, pid, source_plugin)
    if process_name:
        statement = statement.where(ModuleArtifact.process_name.ilike(f"%{process_name}%"))
    return list(db.execute(statement.order_by(ModuleArtifact.pid.asc()).offset(offset).limit(limit)).scalars())


def list_memory_region_artifacts(
    db: Session,
    job_id: UUID,
    pid: int | None = None,
    process_name: str | None = None,
    source_plugin: str | None = None,
    executable_only: bool | None = None,
    suspicious_only: bool | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[MemoryRegionArtifact]:
    validate_analysis_job(db, job_id)
    statement = apply_common_filters(select(MemoryRegionArtifact), MemoryRegionArtifact, job_id, pid, source_plugin)
    if process_name:
        statement = statement.where(MemoryRegionArtifact.process_name.ilike(f"%{process_name}%"))
    if executable_only or suspicious_only:
        statement = statement.where(MemoryRegionArtifact.is_executable.is_(True))
    return list(db.execute(statement.order_by(MemoryRegionArtifact.pid.asc()).offset(offset).limit(limit)).scalars())


def list_yara_matches(
    db: Session,
    job_id: UUID,
    pid: int | None = None,
    source_plugin: str | None = None,
    rule_name: str | None = None,
    target_identifier: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[YaraMatch]:
    validate_analysis_job(db, job_id)
    statement = select(YaraMatch).where(YaraMatch.analysis_job_id == job_id)
    if source_plugin:
        statement = statement.where(YaraMatch.source_plugin == source_plugin)
    if rule_name:
        statement = statement.where(YaraMatch.rule_name == rule_name)
    if target_identifier:
        statement = statement.where(YaraMatch.target_identifier == target_identifier)
    if pid is not None:
        pid_text = str(pid)
        statement = statement.where(
            or_(
                YaraMatch.extra_data["pid"].as_integer() == pid,
                YaraMatch.extra_data["process_id"].as_integer() == pid,
                YaraMatch.target_identifier.in_([pid_text, f"PID {pid_text}", f"pid {pid_text}"]),
            )
        )
    return list(db.execute(statement.order_by(YaraMatch.created_at.asc()).offset(offset).limit(limit)).scalars())
