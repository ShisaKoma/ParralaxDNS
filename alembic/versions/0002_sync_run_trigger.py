"""Record how each synchronization was triggered.

Revision ID: 0002_sync_run_trigger
Revises: 0001_initial_schema
Create Date: 2026-09-14
"""

from alembic import op
import sqlalchemy as sa


revision = "0002_sync_run_trigger"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("sync_runs") as batch:
        batch.add_column(
            sa.Column("trigger", sa.String(length=16), nullable=False, server_default="manual")
        )
        batch.create_check_constraint(
            "ck_sync_runs_trigger", "trigger IN ('manual', 'scheduled', 'collector')"
        )


def downgrade() -> None:
    with op.batch_alter_table("sync_runs") as batch:
        batch.drop_constraint("ck_sync_runs_trigger", type_="check")
        batch.drop_column("trigger")
