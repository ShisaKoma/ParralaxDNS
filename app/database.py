from __future__ import annotations

import json
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Column,
    ForeignKey,
    Index,
    Integer,
    JSON,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    create_engine,
    func,
    inspect,
    select,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Connection, Engine, make_url


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def database_url(value: str) -> str:
    """Accept a SQLAlchemy URL, or the former SQLite file path setting."""
    if "://" in value:
        return value.replace("postgres://", "postgresql+psycopg://", 1)
    if value == ":memory:":
        return "sqlite+pysqlite:///:memory:"
    return f"sqlite+pysqlite:///{Path(value).expanduser().resolve()}"


def json_value(value: Any) -> Any:
    """Read both native JSON values and text stored by the legacy SQLite app."""
    if value is None or not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


METADATA = MetaData()
primary_key = Integer().with_variant(BigInteger, "postgresql")
json_document = JSON().with_variant(JSONB, "postgresql")

domains = Table(
    "domains",
    METADATA,
    Column("id", primary_key, primary_key=True),
    Column("name", String(253), nullable=False),
    Column("lifecycle_status", String(16), nullable=False),
    Column("created_at", String(32), nullable=False),
    Column("updated_at", String(32), nullable=False),
    Column("last_seen_at", String(32)),
    Column("archived_at", String(32)),
    UniqueConstraint("name", name="uq_domains_name"),
    CheckConstraint("lifecycle_status IN ('active', 'archived')", name="ck_domains_lifecycle_status"),
)

sync_runs = Table(
    "sync_runs",
    METADATA,
    Column("id", primary_key, primary_key=True),
    Column("provider", String(128), nullable=False),
    Column("trigger", String(16), nullable=False, server_default="manual"),
    Column("started_at", String(32), nullable=False),
    Column("completed_at", String(32)),
    Column("status", String(16), nullable=False),
    Column("discovered_count", Integer, nullable=False, server_default="0"),
    Column("error_message", Text),
    CheckConstraint("status IN ('running', 'success', 'failed')", name="ck_sync_runs_status"),
    CheckConstraint("trigger IN ('manual', 'scheduled', 'collector')", name="ck_sync_runs_trigger"),
)

domain_sources = Table(
    "domain_sources",
    METADATA,
    Column("id", primary_key, primary_key=True),
    Column("domain_id", primary_key, ForeignKey("domains.id"), nullable=False),
    Column("provider", String(128), nullable=False),
    Column("external_id", String(512), nullable=False),
    Column("lifecycle_status", String(16), nullable=False),
    Column("remote_status", Text),
    Column("metadata_json", json_document, nullable=False),
    Column("created_at", String(32), nullable=False),
    Column("updated_at", String(32), nullable=False),
    Column("last_seen_at", String(32)),
    Column("last_sync_run_id", primary_key, ForeignKey("sync_runs.id")),
    Column("archived_at", String(32)),
    UniqueConstraint("provider", "external_id", name="uq_domain_sources_provider_external_id"),
    CheckConstraint("lifecycle_status IN ('active', 'archived')", name="ck_domain_sources_lifecycle_status"),
)

source_snapshots = Table(
    "source_snapshots",
    METADATA,
    Column("id", primary_key, primary_key=True),
    Column("source_id", primary_key, ForeignKey("domain_sources.id"), nullable=False),
    Column("sync_run_id", primary_key, ForeignKey("sync_runs.id"), nullable=False),
    Column("remote_status", Text),
    Column("lifecycle_status", String(16), nullable=False),
    Column("metadata_json", json_document, nullable=False),
    Column("captured_at", String(32), nullable=False),
    UniqueConstraint("source_id", "sync_run_id", name="uq_source_snapshots_source_run"),
    CheckConstraint("lifecycle_status IN ('active', 'archived')", name="ck_source_snapshots_lifecycle_status"),
)

connectivity_tests = Table(
    "connectivity_tests",
    METADATA,
    Column("id", primary_key, primary_key=True),
    Column("provider", String(128), nullable=False),
    Column("started_at", String(32), nullable=False),
    Column("completed_at", String(32)),
    Column("status", String(16), nullable=False),
    Column("latency_ms", Integer),
    Column("response_preview_json", json_document),
    Column("error_message", Text),
    CheckConstraint("status IN ('running', 'success', 'failed')", name="ck_connectivity_tests_status"),
)

history = Table(
    "history",
    METADATA,
    Column("id", primary_key, primary_key=True),
    Column("domain_id", primary_key, ForeignKey("domains.id"), nullable=False),
    Column("source_id", primary_key, ForeignKey("domain_sources.id")),
    Column("sync_run_id", primary_key, ForeignKey("sync_runs.id")),
    Column("event_type", String(32), nullable=False),
    Column("before_json", json_document),
    Column("after_json", json_document),
    Column("occurred_at", String(32), nullable=False),
    CheckConstraint(
        "event_type IN ('created', 'updated', 'archived', 'restored', 'zone_cloned')",
        name="ck_history_event_type",
    ),
)

Index("idx_sources_domain", domain_sources.c.domain_id)
Index("idx_source_snapshots_source", source_snapshots.c.source_id, source_snapshots.c.captured_at.desc())
Index("idx_history_domain", history.c.domain_id, history.c.occurred_at.desc())
Index("idx_connectivity_tests_provider", connectivity_tests.c.provider, connectivity_tests.c.started_at.desc())
# PostgreSQL gets a GIN JSONB index; SQLite transparently receives a standard
# index, which keeps the same metadata portable for local development.
Index("idx_domain_sources_metadata_json", domain_sources.c.metadata_json, postgresql_using="gin")


class Database:
    """Portable SQLAlchemy persistence with Alembic-managed schema versions."""

    def __init__(self, url_or_path: str):
        self.url = database_url(url_or_path)
        parsed_url = make_url(self.url)
        if parsed_url.drivername.startswith("sqlite") and parsed_url.database and parsed_url.database != ":memory:":
            Path(parsed_url.database).parent.mkdir(parents=True, exist_ok=True)
        connect_args = {"check_same_thread": False} if parsed_url.drivername.startswith("sqlite") else {}
        self.engine: Engine = create_engine(self.url, future=True, pool_pre_ping=not parsed_url.drivername.startswith("sqlite"), connect_args=connect_args)

    @property
    def is_sqlite(self) -> bool:
        return self.engine.dialect.name == "sqlite"

    def _alembic_config(self) -> Config:
        root = Path(__file__).resolve().parent.parent
        config = Config(str(root / "alembic.ini"))
        config.set_main_option("script_location", str(root / "alembic"))
        config.set_main_option("sqlalchemy.url", self.url.replace("%", "%%"))
        return config

    def initialize(self, apply_migrations: bool | None = None) -> None:
        """Apply migrations, or safely adopt a pre-Alembic SQLite database."""
        if apply_migrations is None:
            apply_migrations = os.getenv("RUN_MIGRATIONS", "true").lower() in {"1", "true", "yes"}
        inspector = inspect(self.engine)
        table_names = set(inspector.get_table_names())
        config = self._alembic_config()
        if not apply_migrations:
            self._assert_current_schema(config, table_names)
            return
        if "domains" in table_names and "alembic_version" not in table_names:
            # Existing Parralax-DNS SQLite databases have the same logical tables.
            # Creating missing tables is non-destructive, then Alembic records the
            # baseline so no history is rewritten or discarded.
            METADATA.create_all(self.engine)
            self._ensure_legacy_columns()
            command.stamp(config, "head")
            return
        command.upgrade(config, "head")

    def _assert_current_schema(self, config: Config, table_names: set[str]) -> None:
        if "alembic_version" not in table_names:
            raise RuntimeError("La base n'est pas migrée. Exécutez Alembic avec le compte de migration avant de démarrer l'application.")
        with self.engine.connect() as conn:
            version = conn.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one_or_none()
        if version != ScriptDirectory.from_config(config).get_current_head():
            raise RuntimeError("La base n'est pas à jour. Exécutez Alembic avec le compte de migration avant de démarrer l'application.")

    def _ensure_legacy_columns(self) -> None:
        source_columns = {column["name"] for column in inspect(self.engine).get_columns("domain_sources")}
        run_columns = {column["name"] for column in inspect(self.engine).get_columns("sync_runs")}
        if "last_sync_run_id" not in source_columns:
            # This is used only once for SQLite databases produced before the
            # field existed. Runtime queries themselves are SQLAlchemy portable.
            with self.engine.begin() as conn:
                conn.exec_driver_sql("ALTER TABLE domain_sources ADD COLUMN last_sync_run_id INTEGER")
        if "trigger" not in run_columns:
            with self.engine.begin() as conn:
                conn.exec_driver_sql("ALTER TABLE sync_runs ADD COLUMN trigger TEXT NOT NULL DEFAULT 'manual'")

    @contextmanager
    def connection(self) -> Iterator[Connection]:
        with self.engine.begin() as conn:
            yield conn

    def close(self) -> None:
        self.engine.dispose()

    def list_domains(self, include_archived: bool = False) -> list[dict[str, Any]]:
        statement = select(domains).order_by(func.lower(domains.c.name))
        if not include_archived:
            statement = statement.where(domains.c.lifecycle_status == "active")
        with self.connection() as conn:
            result = [dict(row) for row in conn.execute(statement).mappings()]
            for domain in result:
                rows = conn.execute(
                    select(domain_sources)
                    .where(domain_sources.c.domain_id == domain["id"])
                    .order_by(domain_sources.c.provider)
                ).mappings()
                domain["sources"] = [self._source_dict(row) for row in rows]
            return result

    def get_domain(self, domain_id: int) -> dict[str, Any] | None:
        with self.connection() as conn:
            row = conn.execute(select(domains).where(domains.c.id == domain_id)).mappings().first()
            if row is None:
                return None
            domain = dict(row)
            domain["sources"] = [
                self._source_dict(source)
                for source in conn.execute(
                    select(domain_sources)
                    .where(domain_sources.c.domain_id == domain_id)
                    .order_by(domain_sources.c.provider)
                ).mappings()
            ]
            domain["history"] = [
                self._history_dict(item)
                for item in conn.execute(
                    select(history)
                    .where(history.c.domain_id == domain_id)
                    .order_by(history.c.occurred_at.desc(), history.c.id.desc())
                ).mappings()
            ]
            return domain

    def list_history(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return the cross-domain audit trail, enriched for the history UI."""
        statement = (
            select(
                history,
                domains.c.name.label("domain_name"),
                domain_sources.c.provider.label("source_provider"),
                domain_sources.c.external_id.label("source_external_id"),
                sync_runs.c.trigger.label("trigger"),
            )
            .select_from(
                history.join(domains, domains.c.id == history.c.domain_id)
                .outerjoin(domain_sources, domain_sources.c.id == history.c.source_id)
                .outerjoin(sync_runs, sync_runs.c.id == history.c.sync_run_id)
            )
            .order_by(history.c.occurred_at.desc(), history.c.id.desc())
            .limit(limit)
        )
        with self.connection() as conn:
            return [self._history_dict(row) for row in conn.execute(statement).mappings()]

    def source(self, source_id: int) -> dict[str, Any] | None:
        with self.connection() as conn:
            row = conn.execute(
                select(domain_sources, domains.c.name.label("domain_name"))
                .join(domains, domains.c.id == domain_sources.c.domain_id)
                .where(domain_sources.c.id == source_id)
            ).mappings().first()
            return self._source_dict(row) if row else None

    def list_source_snapshots(self, source_id: int) -> list[dict[str, Any]]:
        """Return every successful synchronization snapshot for one source."""
        statement = (
            select(
                source_snapshots,
                sync_runs.c.provider.label("run_provider"),
                sync_runs.c.trigger.label("trigger"),
                sync_runs.c.started_at.label("run_started_at"),
                sync_runs.c.completed_at.label("run_completed_at"),
            )
            .join(sync_runs, sync_runs.c.id == source_snapshots.c.sync_run_id)
            .where(source_snapshots.c.source_id == source_id, sync_runs.c.status == "success")
            .order_by(source_snapshots.c.captured_at.desc(), source_snapshots.c.id.desc())
        )
        with self.connection() as conn:
            return [self._snapshot_dict(row) for row in conn.execute(statement).mappings()]

    def source_snapshot(self, source_id: int, sync_run_id: int) -> dict[str, Any] | None:
        statement = (
            select(
                source_snapshots,
                sync_runs.c.provider.label("run_provider"),
                sync_runs.c.trigger.label("trigger"),
                sync_runs.c.started_at.label("run_started_at"),
                sync_runs.c.completed_at.label("run_completed_at"),
            )
            .join(sync_runs, sync_runs.c.id == source_snapshots.c.sync_run_id)
            .where(
                source_snapshots.c.source_id == source_id,
                source_snapshots.c.sync_run_id == sync_run_id,
                sync_runs.c.status == "success",
            )
        )
        with self.connection() as conn:
            row = conn.execute(statement).mappings().first()
            return self._snapshot_dict(row) if row else None

    def start_connectivity_test(self, provider: str) -> int:
        with self.connection() as conn:
            result = conn.execute(
                connectivity_tests.insert().values(provider=provider, started_at=now(), status="running")
            )
            return int(result.inserted_primary_key[0])

    def finish_connectivity_test(
        self,
        test_id: int,
        *,
        status: str,
        latency_ms: int,
        preview: dict[str, Any] | None = None,
        error_message: str | None = None,
    ) -> None:
        if status not in {"success", "failed"}:
            raise ValueError("Le statut d'un test doit être success ou failed.")
        with self.connection() as conn:
            conn.execute(
                connectivity_tests.update()
                .where(connectivity_tests.c.id == test_id)
                .values(
                    completed_at=now(),
                    status=status,
                    latency_ms=latency_ms,
                    response_preview_json=preview,
                    error_message=error_message,
                )
            )

    def connectivity_test(self, test_id: int) -> dict[str, Any] | None:
        with self.connection() as conn:
            row = conn.execute(
                select(connectivity_tests).where(connectivity_tests.c.id == test_id)
            ).mappings().first()
            return self._connectivity_test_dict(row) if row else None

    def list_connectivity_tests(self, limit: int = 30) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                select(connectivity_tests)
                .order_by(connectivity_tests.c.started_at.desc(), connectivity_tests.c.id.desc())
                .limit(limit)
            ).mappings()
            return [self._connectivity_test_dict(row) for row in rows]

    def counts(self) -> dict[str, int]:
        with self.connection() as conn:
            return {
                table.name: int(conn.execute(select(func.count()).select_from(table)).scalar_one())
                for table in (domains, sync_runs, domain_sources, source_snapshots, connectivity_tests, history)
            }

    @staticmethod
    def _source_dict(row: Mapping[str, Any]) -> dict[str, Any]:
        item = dict(row)
        item["metadata"] = json_value(item.pop("metadata_json"))
        return item

    @staticmethod
    def _history_dict(row: Mapping[str, Any]) -> dict[str, Any]:
        item = dict(row)
        item["before"] = json_value(item.pop("before_json"))
        item["after"] = json_value(item.pop("after_json"))
        return item

    @staticmethod
    def _snapshot_dict(row: Mapping[str, Any]) -> dict[str, Any]:
        item = dict(row)
        item["metadata"] = json_value(item.pop("metadata_json"))
        return item

    @staticmethod
    def _connectivity_test_dict(row: Mapping[str, Any]) -> dict[str, Any]:
        item = dict(row)
        item["response_preview"] = json_value(item.pop("response_preview_json"))
        return item
