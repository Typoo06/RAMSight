# Risk finding model.

from sqlalchemy import ForeignKey, Integer, JSON, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin, UpdatedAtMixin
from app.models.enums import OSFamily, OSScope, Severity


class RiskFinding(UUIDPrimaryKeyMixin, CreatedAtMixin, UpdatedAtMixin, Base):

    __tablename__ = "risk_findings"

    analysis_job_id = mapped_column(Uuid, ForeignKey("analysis_jobs.id"), nullable=False, index=True)
    evidence_id = mapped_column(Uuid, ForeignKey("evidences.id"), nullable=False, index=True)
    plugin_result_id = mapped_column(Uuid, ForeignKey("plugin_results.id"), nullable=True, index=True)
    os_family: Mapped[str] = mapped_column(String(20), default=OSFamily.UNKNOWN.value, index=True, nullable=False)
    os_scope: Mapped[str] = mapped_column(String(20), default=OSScope.ALL.value, index=True, nullable=False)
    source_plugin: Mapped[str | None] = mapped_column(String(255), index=True)
    rule_id: Mapped[str | None] = mapped_column(String(255), index=True)
    rule_name: Mapped[str | None] = mapped_column(String(255), index=True)
    category: Mapped[str | None] = mapped_column(String(100), index=True)
    severity: Mapped[str] = mapped_column(String(20), default=Severity.LOW.value, index=True, nullable=False)
    score: Mapped[int] = mapped_column(Integer, default=0, index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    artifact_type: Mapped[str | None] = mapped_column(String(100), index=True)
    artifact_id: Mapped[str | None] = mapped_column(String(100), index=True)
    recommendation: Mapped[str | None] = mapped_column(Text)
    extra_data: Mapped[dict | None] = mapped_column(JSON)

    iocs = relationship("IOC", back_populates="risk_finding")
