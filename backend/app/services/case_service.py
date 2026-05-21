"""Case service functions."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Case
from app.schemas.case import CaseCreate
from app.services.errors import ConflictError, NotFoundError


def create_case(db: Session, data: CaseCreate) -> Case:
    """Create an investigation case."""
    existing = db.execute(select(Case).where(Case.case_code == data.case_code)).scalar_one_or_none()
    if existing is not None:
        raise ConflictError("case_code already exists")

    # TODO: connect created_by_id when authentication/current_user exists.
    case = Case(case_code=data.case_code, name=data.name, description=data.description, status=data.status)
    db.add(case)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ConflictError("case_code already exists") from exc
    db.refresh(case)
    return case


def list_cases(db: Session, limit: int = 100, offset: int = 0) -> list[Case]:
    """List cases with pagination."""
    return list(db.execute(select(Case).order_by(Case.created_at.desc()).offset(offset).limit(limit)).scalars())


def get_case(db: Session, case_id: UUID) -> Case:
    """Return one case by id."""
    case = db.get(Case, case_id)
    if case is None:
        raise NotFoundError("case not found")
    return case
