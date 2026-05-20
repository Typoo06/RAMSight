"""Analysis job model."""

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin, UpdatedAtMixin
from app.models.enums import AnalysisJobStatus, OSFamily


class AnalysisJob(UUIDPrimaryKeyMixin, CreatedAtMixin, UpdatedAtMixin, Base):
    """Worker-backed memory analysis job."""

    __tablename__ = "analysis_jobs"

    case_id = mapped_column(Uuid, ForeignKey("cases.id"), nullable=False, index=True)
    evidence_id = mapped_column(Uuid, ForeignKey("evidences.id"), nullable=False, index=True)
    created_by_id = mapped_column(Uuid, ForeignKey("users.id"), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(50), default=AnalysisJobStatus.QUEUED.value, index=True, nullable=False)
    os_family: Mapped[str] = mapped_column(String(20), default=OSFamily.UNKNOWN.value, index=True, nullable=False)
    os_version: Mapped[str | None] = mapped_column(String(255))
    architecture: Mapped[str | None] = mapped_column(String(100))
    kernel_version: Mapped[str | None] = mapped_column(String(255))
    symbol_table: Mapped[str | None] = mapped_column(String(255))
    plugin_profile: Mapped[str | None] = mapped_column(String(100), index=True)
    requested_plugins: Mapped[list[str] | None] = mapped_column(JSON)
    error_message: Mapped[str | None] = mapped_column(Text)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    case = relationship("Case", back_populates="analysis_jobs")
    evidence = relationship("Evidence", back_populates="analysis_jobs")
    created_by = relationship("User", back_populates="analysis_jobs")
    plugin_results = relationship("PluginResult", back_populates="analysis_job")
    reports = relationship("Report", back_populates="analysis_job")
