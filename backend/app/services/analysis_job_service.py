"""Analysis job service functions."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AnalysisJob, Case, Evidence
from app.models.enums import AnalysisJobStatus
from app.schemas.analysis_job import AnalysisJobCreate
from app.services.errors import NotFoundError, ValidationError
from app.services.job_dispatcher import AnalysisJobDispatcher


def create_analysis_job(db: Session, data: AnalysisJobCreate, dispatcher: AnalysisJobDispatcher) -> AnalysisJob:
    """Create a queued analysis job and invoke the dispatcher stub."""
    case = db.get(Case, data.case_id)
    if case is None:
        raise NotFoundError("case not found")
    evidence = db.get(Evidence, data.evidence_id)
    if evidence is None:
        raise NotFoundError("evidence not found")
    if evidence.case_id != data.case_id:
        raise ValidationError("evidence does not belong to case")

    # TODO: connect created_by_id when authentication/current_user exists.
    job = AnalysisJob(
        case_id=data.case_id,
        evidence_id=data.evidence_id,
        status=AnalysisJobStatus.QUEUED.value,
        os_family=data.os_family.value,
        os_version=data.os_version or evidence.os_version,
        architecture=data.architecture or evidence.architecture,
        kernel_version=data.kernel_version or evidence.kernel_version,
        symbol_table=data.symbol_table or evidence.symbol_table,
        plugin_profile=data.plugin_profile,
        requested_plugins=data.requested_plugins,
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    dispatcher.dispatch(job.id)
    return job


def list_analysis_jobs(db: Session, case_id: UUID | None = None, limit: int = 100, offset: int = 0) -> list[AnalysisJob]:
    """List analysis jobs."""
    statement = select(AnalysisJob).order_by(AnalysisJob.created_at.desc()).offset(offset).limit(limit)
    if case_id is not None:
        statement = statement.where(AnalysisJob.case_id == case_id)
    return list(db.execute(statement).scalars())


def get_analysis_job(db: Session, job_id: UUID) -> AnalysisJob:
    """Return one analysis job."""
    job = db.get(AnalysisJob, job_id)
    if job is None:
        raise NotFoundError("analysis job not found")
    return job
