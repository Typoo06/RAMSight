# Plugin result query service.

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AnalysisJob, PluginResult
from app.services.errors import NotFoundError


def validate_analysis_job(db: Session, job_id: UUID) -> AnalysisJob:
    job = db.get(AnalysisJob, job_id)
    if job is None:
        raise NotFoundError("analysis job not found")
    return job


def plugin_result_statement(
    job_id: UUID,
    status: str | None = None,
    plugin_name: str | None = None,
    source_plugin: str | None = None,
):
    statement = select(PluginResult).where(PluginResult.analysis_job_id == job_id)
    if status:
        statement = statement.where(PluginResult.status == status)
    if plugin_name:
        statement = statement.where(PluginResult.plugin_name == plugin_name)
    if source_plugin:
        statement = statement.where(PluginResult.source_plugin == source_plugin)
    return statement


def list_plugin_results(
    db: Session,
    job_id: UUID,
    status: str | None = None,
    plugin_name: str | None = None,
    source_plugin: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[PluginResult]:
    validate_analysis_job(db, job_id)
    statement = plugin_result_statement(job_id, status, plugin_name, source_plugin)
    statement = statement.order_by(PluginResult.created_at.asc()).offset(offset).limit(limit)
    return list(db.execute(statement).scalars())


def count_plugin_results(
    db: Session,
    job_id: UUID,
    status: str | None = None,
    plugin_name: str | None = None,
    source_plugin: str | None = None,
) -> int:
    validate_analysis_job(db, job_id)
    statement = plugin_result_statement(job_id, status, plugin_name, source_plugin)
    return int(db.execute(select(func.count()).select_from(statement.subquery())).scalar_one())


def export_plugin_results(
    db: Session,
    job_id: UUID,
    status: str | None = None,
    plugin_name: str | None = None,
    source_plugin: str | None = None,
) -> list[PluginResult]:
    validate_analysis_job(db, job_id)
    statement = plugin_result_statement(job_id, status, plugin_name, source_plugin).order_by(PluginResult.created_at.asc())
    return list(db.execute(statement).scalars())


def get_plugin_result(db: Session, plugin_result_id: UUID) -> PluginResult:
    plugin_result = db.get(PluginResult, plugin_result_id)
    if plugin_result is None:
        raise NotFoundError("plugin result not found")
    return plugin_result
