# Module artifact model.

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.artifact_mixins import ArtifactLinkMixin
from app.models.base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin


class ModuleArtifact(UUIDPrimaryKeyMixin, ArtifactLinkMixin, CreatedAtMixin, Base):

    __tablename__ = "module_artifacts"

    pid: Mapped[int | None] = mapped_column(Integer, index=True)
    process_name: Mapped[str | None] = mapped_column(String(255))
    module_name: Mapped[str | None] = mapped_column(String(255), index=True)
    module_path: Mapped[str | None] = mapped_column(String(1024))
    base_address: Mapped[str | None] = mapped_column(String(100))
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    load_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
