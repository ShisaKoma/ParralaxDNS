"""Create the portable Parralax-DNS schema.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-09-14
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # This baseline is deliberately explicit. It must not change when the
    # application metadata evolves, otherwise a new installation could receive
    # columns that belong to later Alembic revisions.
    primary_key = sa.Integer().with_variant(sa.BigInteger(), "postgresql")
    json_document = sa.JSON().with_variant(JSONB, "postgresql")

    op.create_table(
        "domains",
        sa.Column("id", primary_key, primary_key=True),
        sa.Column("name", sa.String(length=253), nullable=False),
        sa.Column("lifecycle_status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.String(length=32), nullable=False),
        sa.Column("updated_at", sa.String(length=32), nullable=False),
        sa.Column("last_seen_at", sa.String(length=32)),
        sa.Column("archived_at", sa.String(length=32)),
        sa.UniqueConstraint("name", name="uq_domains_name"),
        sa.CheckConstraint("lifecycle_status IN ('active', 'archived')", name="ck_domains_lifecycle_status"),
    )
    op.create_table(
        "sync_runs",
        sa.Column("id", primary_key, primary_key=True),
        sa.Column("provider", sa.String(length=128), nullable=False),
        sa.Column("started_at", sa.String(length=32), nullable=False),
        sa.Column("completed_at", sa.String(length=32)),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("discovered_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text()),
        sa.CheckConstraint("status IN ('running', 'success', 'failed')", name="ck_sync_runs_status"),
    )
    op.create_table(
        "domain_sources",
        sa.Column("id", primary_key, primary_key=True),
        sa.Column("domain_id", primary_key, sa.ForeignKey("domains.id"), nullable=False),
        sa.Column("provider", sa.String(length=128), nullable=False),
        sa.Column("external_id", sa.String(length=512), nullable=False),
        sa.Column("lifecycle_status", sa.String(length=16), nullable=False),
        sa.Column("remote_status", sa.Text()),
        sa.Column("metadata_json", json_document, nullable=False),
        sa.Column("created_at", sa.String(length=32), nullable=False),
        sa.Column("updated_at", sa.String(length=32), nullable=False),
        sa.Column("last_seen_at", sa.String(length=32)),
        sa.Column("last_sync_run_id", primary_key, sa.ForeignKey("sync_runs.id")),
        sa.Column("archived_at", sa.String(length=32)),
        sa.UniqueConstraint("provider", "external_id", name="uq_domain_sources_provider_external_id"),
        sa.CheckConstraint("lifecycle_status IN ('active', 'archived')", name="ck_domain_sources_lifecycle_status"),
    )
    op.create_table(
        "connectivity_tests",
        sa.Column("id", primary_key, primary_key=True),
        sa.Column("provider", sa.String(length=128), nullable=False),
        sa.Column("started_at", sa.String(length=32), nullable=False),
        sa.Column("completed_at", sa.String(length=32)),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("latency_ms", sa.Integer()),
        sa.Column("response_preview_json", json_document),
        sa.Column("error_message", sa.Text()),
        sa.CheckConstraint("status IN ('running', 'success', 'failed')", name="ck_connectivity_tests_status"),
    )
    op.create_table(
        "history",
        sa.Column("id", primary_key, primary_key=True),
        sa.Column("domain_id", primary_key, sa.ForeignKey("domains.id"), nullable=False),
        sa.Column("source_id", primary_key, sa.ForeignKey("domain_sources.id")),
        sa.Column("sync_run_id", primary_key, sa.ForeignKey("sync_runs.id")),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("before_json", json_document),
        sa.Column("after_json", json_document),
        sa.Column("occurred_at", sa.String(length=32), nullable=False),
        sa.CheckConstraint(
            "event_type IN ('created', 'updated', 'archived', 'restored', 'zone_cloned')",
            name="ck_history_event_type",
        ),
    )
    op.create_index("idx_sources_domain", "domain_sources", ["domain_id"])
    op.create_index("idx_history_domain", "history", ["domain_id", sa.text("occurred_at DESC")])
    op.create_index("idx_connectivity_tests_provider", "connectivity_tests", ["provider", sa.text("started_at DESC")])
    op.create_index("idx_domain_sources_metadata_json", "domain_sources", ["metadata_json"], postgresql_using="gin")


def downgrade() -> None:
    op.drop_index("idx_domain_sources_metadata_json", table_name="domain_sources")
    op.drop_index("idx_connectivity_tests_provider", table_name="connectivity_tests")
    op.drop_index("idx_history_domain", table_name="history")
    op.drop_index("idx_sources_domain", table_name="domain_sources")
    op.drop_table("history")
    op.drop_table("connectivity_tests")
    op.drop_table("domain_sources")
    op.drop_table("sync_runs")
    op.drop_table("domains")
