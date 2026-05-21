"""Report metadata query service."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Report
from app.services.errors import NotFoundError


def list_reports(
    db: Session, case_id: UUID | None = None, job_id: UUID | None = None, limit: int = 100, offset: int = 0
) -> list[Report]:
    """List report metadata by optional case/job filters."""
    statement = select(Report).order_by(Report.created_at.desc())
    if case_id is not None:
        statement = statement.where(Report.case_id == case_id)
    if job_id is not None:
        statement = statement.where(Report.analysis_job_id == job_id)
    return list(db.execute(statement.offset(offset).limit(limit)).scalars())


def get_report(db: Session, report_id: UUID) -> Report:
    """Return one report metadata record."""
    report = db.get(Report, report_id)
    if report is None:
        raise NotFoundError("report not found")
    return report
