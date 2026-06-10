# Analyst note service functions.

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AnalystNote, AnalysisJob, RiskFinding
from app.services.errors import NotFoundError, ValidationError

MAX_NOTE_LENGTH = 4000
DEFAULT_FINDING_NOTE_TYPE = "finding_review"


def clean_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def clean_required_note(value: str | None) -> str:
    content = clean_optional_text(value)
    if content is None:
        raise ValidationError("note content is required")
    if len(content) > MAX_NOTE_LENGTH:
        raise ValidationError(f"note content must be {MAX_NOTE_LENGTH} characters or fewer")
    return content


def validate_note_type(value: str | None) -> str:
    note_type = clean_optional_text(value) or DEFAULT_FINDING_NOTE_TYPE
    if len(note_type) > 50:
        raise ValidationError("note_type must be 50 characters or fewer")
    if not note_type.replace("_", "").replace("-", "").isalnum():
        raise ValidationError("note_type may only contain letters, numbers, dashes, and underscores")
    return note_type


def get_finding(db: Session, finding_id: UUID) -> RiskFinding:
    finding = db.get(RiskFinding, finding_id)
    if finding is None:
        raise NotFoundError("risk finding not found")
    return finding


def create_finding_note(
    db: Session,
    finding_id: UUID,
    content: str | None,
    author_name: str | None = None,
    note_type: str | None = DEFAULT_FINDING_NOTE_TYPE,
    commit: bool = True,
) -> AnalystNote:
    finding = get_finding(db, finding_id)
    job = db.get(AnalysisJob, finding.analysis_job_id)
    if job is None:
        raise NotFoundError("analysis job not found")

    note = AnalystNote(
        case_id=job.case_id,
        evidence_id=finding.evidence_id,
        analysis_job_id=finding.analysis_job_id,
        risk_finding_id=finding.id,
        note_type=validate_note_type(note_type),
        author_name=clean_optional_text(author_name),
        body=clean_required_note(content),
    )
    db.add(note)
    if commit:
        db.commit()
        db.refresh(note)
    else:
        db.flush()
    return note


def list_finding_notes(db: Session, finding_id: UUID, limit: int = 100, offset: int = 0) -> list[AnalystNote]:
    get_finding(db, finding_id)
    statement = (
        select(AnalystNote)
        .where(AnalystNote.risk_finding_id == finding_id)
        .order_by(AnalystNote.created_at.asc(), AnalystNote.id.asc())
        .offset(offset)
        .limit(limit)
    )
    return list(db.execute(statement).scalars())
