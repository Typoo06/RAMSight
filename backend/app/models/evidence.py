# Evidence model.

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin, UpdatedAtMixin
from app.models.enums import EvidenceSourceType, OSFamily


class Evidence(UUIDPrimaryKeyMixin, CreatedAtMixin, UpdatedAtMixin, Base):

    __tablename__ = "evidences"

    case_id = mapped_column(Uuid, ForeignKey("cases.id"), nullable=False, index=True)
    uploaded_by_id = mapped_column(Uuid, ForeignKey("users.id"), nullable=True, index=True)
    source_type: Mapped[str] = mapped_column(String(50), default=EvidenceSourceType.UPLOAD.value, nullable=False)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    content_type: Mapped[str | None] = mapped_column(String(255))
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    md5: Mapped[str | None] = mapped_column(String(32), index=True)
    sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    storage_bucket: Mapped[str | None] = mapped_column(String(255))
    storage_key: Mapped[str | None] = mapped_column(String(1024))
    local_path: Mapped[str | None] = mapped_column(String(1024))
    os_family: Mapped[str] = mapped_column(String(20), default=OSFamily.UNKNOWN.value, index=True, nullable=False)
    os_version: Mapped[str | None] = mapped_column(String(255))
    architecture: Mapped[str | None] = mapped_column(String(100))
    kernel_version: Mapped[str | None] = mapped_column(String(255))
    symbol_table: Mapped[str | None] = mapped_column(String(255))
    acquisition_tool: Mapped[str | None] = mapped_column(String(255))
    acquisition_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    case = relationship("Case", back_populates="evidences")
    uploaded_by = relationship("User", back_populates="evidences")
    analysis_jobs = relationship("AnalysisJob", back_populates="evidence")
    plugin_results = relationship("PluginResult", back_populates="evidence")
    reports = relationship("Report", back_populates="evidence")
