"""Risk finding query service."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AnalysisJob, RiskFinding


def list_risk_findings(
    db: Session, case_id: UUID | None = None, job_id: UUID | None = None, limit: int = 100, offset: int = 0
) -> list[RiskFinding]:
    """List risk findings by optional case/job filters."""
    statement = select(RiskFinding).order_by(RiskFinding.score.desc(), RiskFinding.created_at.desc())
    if case_id is not None:
        statement = statement.join(AnalysisJob, RiskFinding.analysis_job_id == AnalysisJob.id).where(
            AnalysisJob.case_id == case_id
        )
    if job_id is not None:
        statement = statement.where(RiskFinding.analysis_job_id == job_id)
    return list(db.execute(statement.offset(offset).limit(limit)).scalars())
