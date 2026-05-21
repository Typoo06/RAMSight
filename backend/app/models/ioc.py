# Indicator of compromise model.

from sqlalchemy import ForeignKey, Integer, JSON, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin, UpdatedAtMixin
from app.models.enums import OSFamily


class IOC(UUIDPrimaryKeyMixin, CreatedAtMixin, UpdatedAtMixin, Base):

    __tablename__ = "iocs"

    analysis_job_id = mapped_column(Uuid, ForeignKey("analysis_jobs.id"), nullable=False, index=True)
    evidence_id = mapped_column(Uuid, ForeignKey("evidences.id"), nullable=False, index=True)
    risk_finding_id = mapped_column(Uuid, ForeignKey("risk_findings.id"), nullable=True, index=True)
    os_family: Mapped[str] = mapped_column(String(20), default=OSFamily.UNKNOWN.value, index=True, nullable=False)
    source_plugin: Mapped[str | None] = mapped_column(String(255), index=True)
    ioc_type: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    value: Mapped[str] = mapped_column(String(1024), index=True, nullable=False)
    normalized_value: Mapped[str | None] = mapped_column(String(1024), index=True)
    context: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[int | None] = mapped_column(Integer)
    extra_data: Mapped[dict | None] = mapped_column(JSON)

    risk_finding = relationship("RiskFinding", back_populates="iocs")
