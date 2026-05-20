"""Shared SQLAlchemy model base and mixins."""

from datetime import datetime, timezone
import uuid

from sqlalchemy import DateTime, Uuid
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utc_now() -> datetime:
    """Return timezone-aware UTC timestamps for model defaults."""
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Declarative base for all backend models."""


class UUIDPrimaryKeyMixin:
    """UUID primary key shared by all tables."""

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)


class CreatedAtMixin:
    """Created timestamp shared by persisted records."""

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class UpdatedAtMixin:
    """Updated timestamp for mutable records."""

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )
