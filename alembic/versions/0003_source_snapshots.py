"""Store complete source snapshots for each successful synchronization.

Revision ID: 0003_source_snapshots
Revises: 0002_sync_run_trigger
Create Date: 2026-09-15
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision = "0003_source_snapshots"
down_revision = "0002_sync_run_trigger"
branch_labels = None
depends_on = None


def upgrade() -> None:
    primary_key = sa.Integer().with_variant(sa.BigInteger(), "postgresql")
    json_document = sa.JSON().with_variant(JSONB, "postgresql")
    op.create_table(
        "source_snapshots",
        sa.Column("id", primary_key, primary_key=True),
        sa.Column("source_id", primary_key, sa.ForeignKey("domain_sources.id"), nullable=False),
        sa.Column("sync_run_id", primary_key, sa.ForeignKey("sync_runs.id"), nullable=False),
        sa.Column("remote_status", sa.Text()),
        sa.Column("lifecycle_status", sa.String(length=16), nullable=False),
        sa.Column("metadata_json", json_document, nullable=False),
        sa.Column("captured_at", sa.String(length=32), nullable=False),
        sa.UniqueConstraint("source_id", "sync_run_id", name="uq_source_snapshots_source_run"),
        sa.CheckConstraint("lifecycle_status IN ('active', 'archived')", name="ck_source_snapshots_lifecycle_status"),
    )
    op.create_index("idx_source_snapshots_source", "source_snapshots", ["source_id", sa.text("captured_at DESC")])


def downgrade() -> None:
    op.drop_index("idx_source_snapshots_source", table_name="source_snapshots")
    op.drop_table("source_snapshots")
