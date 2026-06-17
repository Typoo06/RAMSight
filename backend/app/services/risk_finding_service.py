# Risk finding query and review service.

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AnalysisJob, RiskFinding
from app.models.base import utc_now
from app.schemas.risk_finding import RiskFindingReviewUpdate
from app.services import analyst_note_service
from app.services.errors import NotFoundError, ValidationError

REVIEW_STATUSES = {"new", "investigating", "reviewed"}
ANALYST_VERDICTS = {"true_positive", "false_positive", "benign", "suspicious", "needs_more_evidence", "ignored"}
SEVERITIES = {"low", "medium", "high", "critical"}


def clean_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def validate_choice(value: str | None, allowed: set[str], field_name: str) -> str | None:
    cleaned = clean_optional_text(value)
    if cleaned is None:
        return None
    normalized = cleaned.lower()
    if normalized not in allowed:
        raise ValidationError(f"invalid {field_name}")
    return normalized


def get_risk_finding(db: Session, finding_id: UUID) -> RiskFinding:
    finding = db.get(RiskFinding, finding_id)
    if finding is None:
        raise NotFoundError("risk finding not found")
    return finding


def list_risk_findings(
    db: Session,
    case_id: UUID | None = None,
    job_id: UUID | None = None,
    review_status: str | None = None,
    analyst_verdict: str | None = None,
    severity_effective: str | None = None,
    category: str | None = None,
    source_plugin: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[RiskFinding]:
    statement = risk_finding_statement(case_id, job_id, review_status, analyst_verdict, severity_effective, category, source_plugin)
    return list(db.execute(statement.order_by(RiskFinding.score.desc(), RiskFinding.created_at.desc()).offset(offset).limit(limit)).scalars())


def risk_finding_statement(
    case_id: UUID | None = None,
    job_id: UUID | None = None,
    review_status: str | None = None,
    analyst_verdict: str | None = None,
    severity_effective: str | None = None,
    category: str | None = None,
    source_plugin: str | None = None,
):
    statement = select(RiskFinding)
    if case_id is not None:
        statement = statement.join(AnalysisJob, RiskFinding.analysis_job_id == AnalysisJob.id).where(
            AnalysisJob.case_id == case_id
        )
    if job_id is not None:
        statement = statement.where(RiskFinding.analysis_job_id == job_id)
    if review_status is not None:
        statement = statement.where(RiskFinding.review_status == validate_choice(review_status, REVIEW_STATUSES, "review_status"))
    if analyst_verdict is not None:
        statement = statement.where(
            RiskFinding.analyst_verdict == validate_choice(analyst_verdict, ANALYST_VERDICTS, "analyst_verdict")
        )
    if severity_effective is not None:
        statement = statement.where(
            func.coalesce(RiskFinding.severity_override, RiskFinding.severity)
            == validate_choice(severity_effective, SEVERITIES, "severity_effective")
        )
    if category is not None:
        cleaned_category = clean_optional_text(category)
        if cleaned_category is not None:
            statement = statement.where(RiskFinding.category == cleaned_category)
    if source_plugin is not None:
        cleaned_source_plugin = clean_optional_text(source_plugin)
        if cleaned_source_plugin is not None:
            statement = statement.where(RiskFinding.source_plugin == cleaned_source_plugin)
    return statement


def count_risk_findings(
    db: Session,
    case_id: UUID | None = None,
    job_id: UUID | None = None,
    review_status: str | None = None,
    analyst_verdict: str | None = None,
    severity_effective: str | None = None,
    category: str | None = None,
    source_plugin: str | None = None,
) -> int:
    statement = risk_finding_statement(case_id, job_id, review_status, analyst_verdict, severity_effective, category, source_plugin)
    return int(db.execute(select(func.count()).select_from(statement.subquery())).scalar_one())


def export_risk_findings(
    db: Session,
    case_id: UUID | None = None,
    job_id: UUID | None = None,
    review_status: str | None = None,
    analyst_verdict: str | None = None,
    severity_effective: str | None = None,
    category: str | None = None,
    source_plugin: str | None = None,
) -> list[RiskFinding]:
    statement = risk_finding_statement(
        case_id, job_id, review_status, analyst_verdict, severity_effective, category, source_plugin
    )
    return list(db.execute(statement.order_by(RiskFinding.score.desc(), RiskFinding.created_at.desc())).scalars())


def update_review(db: Session, finding_id: UUID, data: RiskFindingReviewUpdate) -> RiskFinding:
    finding = get_risk_finding(db, finding_id)
    updates = data.model_dump(exclude_unset=True)

    if "review_status" in updates:
        review_status = validate_choice(updates["review_status"], REVIEW_STATUSES, "review_status")
        if review_status is None:
            raise ValidationError("invalid review_status")
        finding.review_status = review_status
        if review_status == "reviewed" and finding.reviewed_at is None:
            finding.reviewed_at = utc_now()

    if "analyst_verdict" in updates:
        finding.analyst_verdict = validate_choice(updates["analyst_verdict"], ANALYST_VERDICTS, "analyst_verdict")

    if "severity_override" in updates:
        finding.severity_override = validate_choice(updates["severity_override"], SEVERITIES, "severity_override")

    if "reviewed_by_name" in updates:
        finding.reviewed_by_name = clean_optional_text(updates["reviewed_by_name"])

    finding.review_updated_at = utc_now()

    if "note" in updates and clean_optional_text(updates["note"]) is not None:
        analyst_note_service.create_finding_note(
            db,
            finding_id=finding.id,
            content=updates["note"],
            author_name=finding.reviewed_by_name,
            note_type="finding_review",
            commit=False,
        )

    db.commit()
    db.refresh(finding)
    return finding
