# Widen YARA match offsets for x64 memory addresses.

from alembic import op
import sqlalchemy as sa

revision = "0002_yara_match_offset_bigint"
down_revision = "0001_initial_os_aware_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "yara_matches",
        "offset",
        existing_type=sa.Integer(),
        type_=sa.BigInteger(),
        existing_nullable=True,
    )


def downgrade() -> None:
    # This can fail if stored offsets exceed the PostgreSQL INTEGER range.
    op.alter_column(
        "yara_matches",
        "offset",
        existing_type=sa.BigInteger(),
        type_=sa.Integer(),
        existing_nullable=True,
    )
