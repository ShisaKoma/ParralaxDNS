"""Store immutable reports produced by network diagnostic agents.

Revision ID: 0004_network_diagnostics
Revises: 0003_source_snapshots
Create Date: 2026-09-25
"""

from alembic import op
import sqlalchemy as sa


revision = "0004_network_diagnostics"
down_revision = "0003_source_snapshots"
branch_labels = None
depends_on = None


def upgrade() -> None:
    primary_key = sa.Integer().with_variant(sa.BigInteger(), "postgresql")
    op.create_table(
        "network_diagnostic_runs",
        sa.Column("id", primary_key, primary_key=True),
        sa.Column("agent", sa.String(length=128), nullable=False),
        sa.Column("collected_at", sa.String(length=32), nullable=False),
        sa.Column("received_at", sa.String(length=32), nullable=False),
        sa.Column("complete", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("check_count", sa.Integer(), nullable=False),
        sa.Column("anomaly_count", sa.Integer(), nullable=False),
        sa.CheckConstraint("status IN ('success', 'partial')", name="ck_network_diagnostic_runs_status"),
    )
    op.create_table(
        "network_diagnostic_results",
        sa.Column("id", primary_key, primary_key=True),
        sa.Column("run_id", primary_key, sa.ForeignKey("network_diagnostic_runs.id"), nullable=False),
        sa.Column("domain", sa.String(length=253)),
        sa.Column("check_type", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("exit_code", sa.Integer()),
        sa.Column("duration_ms", sa.Integer()),
        sa.Column("anomaly_code", sa.String(length=64)),
        sa.Column("output", sa.Text(), nullable=False),
        sa.CheckConstraint(
            "status IN ('ok', 'anomaly', 'error', 'unavailable')",
            name="ck_network_diagnostic_results_status",
        ),
    )
    op.create_index(
        "idx_network_diagnostic_runs_agent",
        "network_diagnostic_runs",
        ["agent", sa.text("collected_at DESC")],
    )
    op.create_index("idx_network_diagnostic_results_run", "network_diagnostic_results", ["run_id"])
    op.create_index(
        "idx_network_diagnostic_results_anomalies",
        "network_diagnostic_results",
        ["status", "domain"],
    )


def downgrade() -> None:
    op.drop_index("idx_network_diagnostic_results_anomalies", table_name="network_diagnostic_results")
    op.drop_index("idx_network_diagnostic_results_run", table_name="network_diagnostic_results")
    op.drop_index("idx_network_diagnostic_runs_agent", table_name="network_diagnostic_runs")
    op.drop_table("network_diagnostic_results")
    op.drop_table("network_diagnostic_runs")
