# Report model.

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin, UpdatedAtMixin
from app.models.enums import OSFamily, ReportFormat, ReportType


class Report(UUIDPrimaryKeyMixin, CreatedAtMixin, UpdatedAtMixin, Base):

    __tablename__ = "reports"

    case_id = mapped_column(Uuid, ForeignKey("cases.id"), nullable=False, index=True)
    evidence_id = mapped_column(Uuid, ForeignKey("evidences.id"), nullable=False, index=True)
    analysis_job_id = mapped_column(Uuid, ForeignKey("analysis_jobs.id"), nullable=False, index=True)
    os_family: Mapped[str] = mapped_column(String(20), default=OSFamily.UNKNOWN.value, index=True, nullable=False)
    report_type: Mapped[str] = mapped_column(String(50), default=ReportType.TECHNICAL.value, index=True, nullable=False)
    format: Mapped[str] = mapped_column(String(20), default=ReportFormat.HTML.value, index=True, nullable=False)
    storage_bucket: Mapped[str | None] = mapped_column(String(255))
    storage_key: Mapped[str | None] = mapped_column(String(1024))
    generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    case = relationship("Case", back_populates="reports")
    evidence = relationship("Evidence", back_populates="reports")
    analysis_job = relationship("AnalysisJob", back_populates="reports")
