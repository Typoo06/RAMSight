# Process artifact model.

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.artifact_mixins import ArtifactLinkMixin
from app.models.base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin


class ProcessArtifact(UUIDPrimaryKeyMixin, ArtifactLinkMixin, CreatedAtMixin, Base):

    __tablename__ = "process_artifacts"

    pid: Mapped[int | None] = mapped_column(Integer, index=True)
    ppid: Mapped[int | None] = mapped_column(Integer, index=True)
    name: Mapped[str | None] = mapped_column(String(255), index=True)
    image_path: Mapped[str | None] = mapped_column(String(1024))
    command_line: Mapped[str | None] = mapped_column(Text)
    user_name: Mapped[str | None] = mapped_column(String(255))
    session_id: Mapped[int | None] = mapped_column(Integer)
    created_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    exited_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_hidden_candidate: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
