"""Copy a Parralax-DNS SQLite inventory to a freshly migrated PostgreSQL database.

The source is never modified. A timestamped backup is created before copying,
then every application table is counted on both sides before success is reported.
"""

from __future__ import annotations

import argparse
import json
import shutil
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import MetaData, Table, create_engine, func, inspect, select, text

from .database import (
    Database,
    connectivity_tests,
    database_url,
    domain_sources,
    domains,
    history,
    source_snapshots,
    json_value,
    sync_runs,
)


TABLES = (domains, sync_runs, domain_sources, source_snapshots, connectivity_tests, history)
JSON_COLUMNS = {"metadata_json", "response_preview_json", "before_json", "after_json"}


@dataclass(frozen=True)
class MigrationReport:
    backup_path: str
    source_counts: dict[str, int]
    target_counts: dict[str, int]


class MigrationError(RuntimeError):
    pass


def _sqlite_path(source_url: str) -> Path:
    from sqlalchemy.engine import make_url

    parsed = make_url(source_url)
    if not parsed.drivername.startswith("sqlite") or not parsed.database or parsed.database == ":memory:":
        raise MigrationError("La source doit être un fichier SQLite, pas une base en mémoire ou une autre URL.")
    return Path(parsed.database)


def _rows(engine, table_name: str) -> list[dict[str, Any]]:
    inspector = inspect(engine)
    if table_name not in inspector.get_table_names():
        return []
    metadata = MetaData()
    table = Table(table_name, metadata, autoload_with=engine)
    with engine.connect() as conn:
        return [dict(row) for row in conn.execute(select(table)).mappings()]


def _prepare_rows(rows: list[dict[str, Any]], target_table: Table) -> list[dict[str, Any]]:
    target_columns = {column.name for column in target_table.columns}
    prepared = []
    for row in rows:
        item = {name: row.get(name) for name in target_columns if name in row}
        for name in JSON_COLUMNS & item.keys():
            item[name] = json_value(item[name])
        prepared.append(item)
    return prepared


def _reset_sequences(connection) -> None:
    # IDs are preserved so foreign-key history remains immutable. PostgreSQL
    # sequences must therefore move beyond the imported maximum values.
    for table in TABLES:
        maximum_id = connection.scalar(select(func.max(table.c.id))) or 1
        connection.execute(
            text("SELECT setval(pg_get_serial_sequence(:table_name, 'id'), :maximum_id, true)"),
            {"table_name": table.name, "maximum_id": maximum_id},
        )


def migrate(source: str, target: str, backup_dir: str) -> MigrationReport:
    source_url = database_url(source)
    target_url = database_url(target)
    if not target_url.startswith("postgresql"):
        raise MigrationError("La cible doit être une URL PostgreSQL (postgresql+psycopg://...).")
    source_path = _sqlite_path(source_url)
    if not source_path.is_file():
        raise MigrationError(f"Base SQLite introuvable : {source_path}")

    target_db = Database(target_url)
    try:
        target_db.initialize()
        if any(target_db.counts().values()):
            raise MigrationError("La base PostgreSQL cible doit être vide afin d'éviter tout doublon ou écrasement.")

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        destination = Path(backup_dir).expanduser().resolve() / f"{source_path.stem}-{timestamp}.sqlite3"
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, destination)

        source_engine = create_engine(source_url, future=True)
        source_rows = {table.name: _rows(source_engine, table.name) for table in TABLES}
        source_counts = {name: len(rows) for name, rows in source_rows.items()}
        with target_db.engine.begin() as connection:
            for table in TABLES:
                rows = _prepare_rows(source_rows[table.name], table)
                if rows:
                    connection.execute(table.insert(), rows)
            _reset_sequences(connection)
        source_engine.dispose()

        target_counts = target_db.counts()
        if source_counts != target_counts:
            raise MigrationError(
                "Validation des volumes échouée : "
                + json.dumps({"source": source_counts, "target": target_counts}, ensure_ascii=False)
            )
        return MigrationReport(str(destination), source_counts, target_counts)
    finally:
        target_db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Migre une base Parralax-DNS SQLite vers PostgreSQL sans effacer la source.")
    parser.add_argument("--source", required=True, help="Chemin SQLite ou URL sqlite:///…")
    parser.add_argument("--target", required=True, help="URL PostgreSQL cible vide")
    parser.add_argument("--backup-dir", required=True, help="Répertoire hors du dépôt pour la copie de sauvegarde")
    arguments = parser.parse_args()
    report = migrate(arguments.source, arguments.target, arguments.backup_dir)
    print(json.dumps(asdict(report), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
