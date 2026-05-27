# YARA match model.

from sqlalchemy import BigInteger, ForeignKey, JSON, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin
from app.models.enums import OSFamily


class YaraMatch(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):

    __tablename__ = "yara_matches"

    analysis_job_id = mapped_column(Uuid, ForeignKey("analysis_jobs.id"), nullable=False, index=True)
    evidence_id = mapped_column(Uuid, ForeignKey("evidences.id"), nullable=False, index=True)
    plugin_result_id = mapped_column(Uuid, ForeignKey("plugin_results.id"), nullable=True, index=True)
    os_family: Mapped[str] = mapped_column(String(20), default=OSFamily.UNKNOWN.value, index=True, nullable=False)
    source_plugin: Mapped[str | None] = mapped_column(String(255), index=True)
    rule_name: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    namespace: Mapped[str | None] = mapped_column(String(255))
    tags: Mapped[list[str] | None] = mapped_column(JSON)
    target_type: Mapped[str | None] = mapped_column(String(100), index=True)
    target_identifier: Mapped[str | None] = mapped_column(String(255), index=True)
    offset: Mapped[int | None] = mapped_column(BigInteger)
    matched_text_excerpt: Mapped[str | None] = mapped_column(Text)
    extra_data: Mapped[dict | None] = mapped_column(JSON)
