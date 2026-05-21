# Shared fields for OS-aware artifact models.

from sqlalchemy import ForeignKey, JSON, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.models.enums import OSFamily


class ArtifactLinkMixin:

    analysis_job_id = mapped_column(Uuid, ForeignKey("analysis_jobs.id"), nullable=False, index=True)
    evidence_id = mapped_column(Uuid, ForeignKey("evidences.id"), nullable=False, index=True)
    plugin_result_id = mapped_column(Uuid, ForeignKey("plugin_results.id"), nullable=True, index=True)
    os_family: Mapped[str] = mapped_column(String(20), default=OSFamily.UNKNOWN.value, index=True, nullable=False)
    source_plugin: Mapped[str | None] = mapped_column(String(255), index=True)
    raw_record: Mapped[dict | None] = mapped_column(JSON)
