# Case model.

from sqlalchemy import ForeignKey, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin, UpdatedAtMixin


class Case(UUIDPrimaryKeyMixin, CreatedAtMixin, UpdatedAtMixin, Base):

    __tablename__ = "cases"

    case_code: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(50), default="open", index=True, nullable=False)
    created_by_id = mapped_column(Uuid, ForeignKey("users.id"), nullable=True, index=True)

    created_by = relationship("User", back_populates="cases")
    evidences = relationship("Evidence", back_populates="case")
    analysis_jobs = relationship("AnalysisJob", back_populates="case")
    reports = relationship("Report", back_populates="case")
    analyst_notes = relationship("AnalystNote", back_populates="case")
