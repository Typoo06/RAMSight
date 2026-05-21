# Network artifact model.

from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.artifact_mixins import ArtifactLinkMixin
from app.models.base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin


class NetworkArtifact(UUIDPrimaryKeyMixin, ArtifactLinkMixin, CreatedAtMixin, Base):

    __tablename__ = "network_artifacts"

    protocol: Mapped[str | None] = mapped_column(String(50), index=True)
    local_address: Mapped[str | None] = mapped_column(String(255), index=True)
    local_port: Mapped[int | None] = mapped_column(Integer)
    remote_address: Mapped[str | None] = mapped_column(String(255), index=True)
    remote_port: Mapped[int | None] = mapped_column(Integer)
    state: Mapped[str | None] = mapped_column(String(100), index=True)
    pid: Mapped[int | None] = mapped_column(Integer, index=True)
    process_name: Mapped[str | None] = mapped_column(String(255))
    created_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
