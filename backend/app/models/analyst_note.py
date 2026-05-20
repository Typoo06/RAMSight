"""Analyst note model."""

from sqlalchemy import ForeignKey, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin, UpdatedAtMixin


class AnalystNote(UUIDPrimaryKeyMixin, CreatedAtMixin, UpdatedAtMixin, Base):
    """Analyst-authored note attached to case or analysis context."""

    __tablename__ = "analyst_notes"

    case_id = mapped_column(Uuid, ForeignKey("cases.id"), nullable=False, index=True)
    evidence_id = mapped_column(Uuid, ForeignKey("evidences.id"), nullable=True, index=True)
    analysis_job_id = mapped_column(Uuid, ForeignKey("analysis_jobs.id"), nullable=True, index=True)
    created_by_id = mapped_column(Uuid, ForeignKey("users.id"), nullable=True, index=True)
    body: Mapped[str] = mapped_column(Text, nullable=False)

    case = relationship("Case", back_populates="analyst_notes")
    created_by = relationship("User", back_populates="analyst_notes")
