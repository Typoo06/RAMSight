# Add analyst finding review metadata.

from alembic import op
import sqlalchemy as sa

revision = "0003_finding_review_workflow"
down_revision = "0002_yara_match_offset_bigint"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "risk_findings",
        sa.Column("review_status", sa.String(length=30), server_default="new", nullable=False),
    )
    op.add_column("risk_findings", sa.Column("analyst_verdict", sa.String(length=50), nullable=True))
    op.add_column("risk_findings", sa.Column("severity_override", sa.String(length=20), nullable=True))
    op.add_column("risk_findings", sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("risk_findings", sa.Column("reviewed_by_name", sa.String(length=255), nullable=True))
    op.add_column("risk_findings", sa.Column("review_updated_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index(op.f("ix_risk_findings_review_status"), "risk_findings", ["review_status"])
    op.create_index(op.f("ix_risk_findings_analyst_verdict"), "risk_findings", ["analyst_verdict"])

    op.add_column("analyst_notes", sa.Column("risk_finding_id", sa.Uuid(), nullable=True))
    op.add_column(
        "analyst_notes",
        sa.Column("note_type", sa.String(length=50), server_default="general", nullable=False),
    )
    op.add_column("analyst_notes", sa.Column("author_name", sa.String(length=255), nullable=True))
    op.create_foreign_key(
        op.f("fk_analyst_notes_risk_finding_id_risk_findings"),
        "analyst_notes",
        "risk_findings",
        ["risk_finding_id"],
        ["id"],
    )
    op.create_index(op.f("ix_analyst_notes_risk_finding_id"), "analyst_notes", ["risk_finding_id"])
    op.create_index(op.f("ix_analyst_notes_note_type"), "analyst_notes", ["note_type"])


def downgrade() -> None:
    op.drop_index(op.f("ix_analyst_notes_note_type"), table_name="analyst_notes")
    op.drop_index(op.f("ix_analyst_notes_risk_finding_id"), table_name="analyst_notes")
    op.drop_constraint(op.f("fk_analyst_notes_risk_finding_id_risk_findings"), "analyst_notes", type_="foreignkey")
    op.drop_column("analyst_notes", "author_name")
    op.drop_column("analyst_notes", "note_type")
    op.drop_column("analyst_notes", "risk_finding_id")

    op.drop_index(op.f("ix_risk_findings_analyst_verdict"), table_name="risk_findings")
    op.drop_index(op.f("ix_risk_findings_review_status"), table_name="risk_findings")
    op.drop_column("risk_findings", "review_updated_at")
    op.drop_column("risk_findings", "reviewed_by_name")
    op.drop_column("risk_findings", "reviewed_at")
    op.drop_column("risk_findings", "severity_override")
    op.drop_column("risk_findings", "analyst_verdict")
    op.drop_column("risk_findings", "review_status")
