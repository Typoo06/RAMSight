"""User model."""

from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin, UpdatedAtMixin


class User(UUIDPrimaryKeyMixin, CreatedAtMixin, UpdatedAtMixin, Base):
    """Local analyst account."""

    __tablename__ = "users"

    username: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    cases = relationship("Case", back_populates="created_by")
    evidences = relationship("Evidence", back_populates="uploaded_by")
    analysis_jobs = relationship("AnalysisJob", back_populates="created_by")
    analyst_notes = relationship("AnalystNote", back_populates="created_by")
    audit_logs = relationship("AuditLog", back_populates="user")
