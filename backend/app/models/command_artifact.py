# Command artifact model.

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.artifact_mixins import ArtifactLinkMixin
from app.models.base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin


class CommandArtifact(UUIDPrimaryKeyMixin, ArtifactLinkMixin, CreatedAtMixin, Base):

    __tablename__ = "command_artifacts"

    pid: Mapped[int | None] = mapped_column(Integer, index=True)
    process_name: Mapped[str | None] = mapped_column(String(255))
    command: Mapped[str | None] = mapped_column(Text)
    shell_type: Mapped[str | None] = mapped_column(String(100), index=True)
    user_name: Mapped[str | None] = mapped_column(String(255))
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
