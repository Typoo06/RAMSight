# IOC query service.

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AnalysisJob, IOC


def ioc_statement(case_id: UUID | None = None, job_id: UUID | None = None):
    statement = select(IOC)
    if case_id is not None:
        statement = statement.join(AnalysisJob, IOC.analysis_job_id == AnalysisJob.id).where(AnalysisJob.case_id == case_id)
    if job_id is not None:
        statement = statement.where(IOC.analysis_job_id == job_id)
    return statement


def list_iocs(
    db: Session, case_id: UUID | None = None, job_id: UUID | None = None, limit: int = 100, offset: int = 0
) -> list[IOC]:
    statement = ioc_statement(case_id=case_id, job_id=job_id).order_by(IOC.created_at.desc())
    return list(db.execute(statement.offset(offset).limit(limit)).scalars())


def count_iocs(db: Session, case_id: UUID | None = None, job_id: UUID | None = None) -> int:
    statement = ioc_statement(case_id=case_id, job_id=job_id)
    return int(db.execute(select(func.count()).select_from(statement.subquery())).scalar_one())
