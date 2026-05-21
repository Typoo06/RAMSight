# Volatility plugin result model.

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin, UpdatedAtMixin
from app.models.enums import OSFamily, PluginResultStatus


class PluginResult(UUIDPrimaryKeyMixin, CreatedAtMixin, UpdatedAtMixin, Base):

    __tablename__ = "plugin_results"

    analysis_job_id = mapped_column(Uuid, ForeignKey("analysis_jobs.id"), nullable=False, index=True)
    evidence_id = mapped_column(Uuid, ForeignKey("evidences.id"), nullable=False, index=True)
    os_family: Mapped[str] = mapped_column(String(20), default=OSFamily.UNKNOWN.value, index=True, nullable=False)
    plugin_profile: Mapped[str | None] = mapped_column(String(100), index=True)
    plugin_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    source_plugin: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(50), default=PluginResultStatus.PENDING.value, index=True, nullable=False)
    raw_output_bucket: Mapped[str | None] = mapped_column(String(255))
    raw_output_key: Mapped[str | None] = mapped_column(String(1024))
    parsed_output_bucket: Mapped[str | None] = mapped_column(String(255))
    parsed_output_key: Mapped[str | None] = mapped_column(String(1024))
    parsed_record_count: Mapped[int | None] = mapped_column(Integer)
    error_message: Mapped[str | None] = mapped_column(Text)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    extra_data: Mapped[dict | None] = mapped_column(JSON)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    analysis_job = relationship("AnalysisJob", back_populates="plugin_results")
    evidence = relationship("Evidence", back_populates="plugin_results")
