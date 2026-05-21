# Memory region artifact model.

from sqlalchemy import Boolean, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.artifact_mixins import ArtifactLinkMixin
from app.models.base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin


class MemoryRegionArtifact(UUIDPrimaryKeyMixin, ArtifactLinkMixin, CreatedAtMixin, Base):

    __tablename__ = "memory_region_artifacts"

    pid: Mapped[int | None] = mapped_column(Integer, index=True)
    process_name: Mapped[str | None] = mapped_column(String(255))
    start_address: Mapped[str | None] = mapped_column(String(100), index=True)
    end_address: Mapped[str | None] = mapped_column(String(100))
    protection: Mapped[str | None] = mapped_column(String(100), index=True)
    is_executable: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_private: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    hexdump_excerpt: Mapped[str | None] = mapped_column(Text)
    disassembly_excerpt: Mapped[str | None] = mapped_column(Text)
