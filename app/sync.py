from __future__ import annotations

import json
from dataclasses import replace
from typing import Any

from sqlalchemy import select
from sqlalchemy.engine import Connection

from .database import Database, domain_sources, domains, history, json_value, now, source_snapshots, sync_runs
from .models import RemoteDomain
from .providers import Provider


def _dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _as_database_text(value: Any) -> str | None:
    """Preserve malformed structured statuses as stable scalar text."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, (list, dict)):
        return _dump(value)
    return str(value)


class Synchronizer:
    def __init__(self, database: Database):
        self.db = database

    def sync(self, provider: Provider, *, trigger: str = "manual") -> dict[str, Any]:
        if trigger not in {"manual", "scheduled", "collector"}:
            raise ValueError("Le déclencheur de synchronisation est invalide.")
        with self.db.connection() as conn:
            run_id = int(
                conn.execute(
                    sync_runs.insert().values(
                        provider=provider.name,
                        trigger=trigger,
                        started_at=now(),
                        status="running",
                    )
                ).inserted_primary_key[0]
            )
        try:
            remote_domains = [self._with_dns_configuration(provider, remote) for remote in provider.list_domains()]
            with self.db.connection() as conn:
                for remote in remote_domains:
                    self._upsert(conn, run_id, remote)
                archived_sources = self._archive_missing_sources(conn, run_id, provider.name)
                conn.execute(
                    sync_runs.update()
                    .where(sync_runs.c.id == run_id)
                    .values(completed_at=now(), status="success", discovered_count=len(remote_domains))
                )
            return {
                "provider": provider.name,
                "trigger": trigger,
                "status": "success",
                "discovered": len(remote_domains),
                "archived_sources": archived_sources,
            }
        except Exception as exc:
            with self.db.connection() as conn:
                conn.execute(
                    sync_runs.update()
                    .where(sync_runs.c.id == run_id)
                    .values(completed_at=now(), status="failed", error_message=str(exc)[:500])
                )
            raise

    @staticmethod
    def _with_dns_configuration(provider: Provider, remote: RemoteDomain) -> RemoteDomain:
        """Attach the complete DNS zone when the provider exposes it read-only.

        A domain can be registered at a provider while its authoritative zone is
        hosted elsewhere. In that case the domain remains inventoried and its
        source metadata records the read failure instead of aborting the run.
        """
        fetch_records = getattr(provider, "list_dns_records", None)
        if not callable(fetch_records) or "records" in remote.metadata or "dns_records" in remote.metadata:
            return remote
        metadata = dict(remote.metadata)
        try:
            identifier = remote.external_id if remote.provider == "cloudflare" else remote.name
            metadata["dns_records"] = fetch_records(identifier)
        except Exception as exc:
            metadata["dns_records_error"] = str(exc)[:500]
        return replace(remote, metadata=metadata)

    def _upsert(self, conn: Connection, run_id: int, remote: RemoteDomain) -> None:
        timestamp = now()
        normalized_name = remote.name.rstrip(".").lower()
        remote_status = _as_database_text(remote.remote_status)
        domain = conn.execute(
            select(domains).where(domains.c.name == normalized_name)
        ).mappings().first()
        if domain is None:
            domain_id = int(
                conn.execute(
                    domains.insert().values(
                        name=normalized_name,
                        lifecycle_status="active",
                        created_at=timestamp,
                        updated_at=timestamp,
                        last_seen_at=timestamp,
                    )
                ).inserted_primary_key[0]
            )
            self._history(conn, domain_id, None, run_id, "created", None, {"name": normalized_name, "lifecycle_status": "active"})
        else:
            domain_id = int(domain["id"])

        source = conn.execute(
            select(domain_sources).where(
                domain_sources.c.provider == remote.provider,
                domain_sources.c.external_id == remote.external_id,
            )
        ).mappings().first()
        current = {"remote_status": remote_status, "metadata": remote.metadata, "lifecycle_status": "active"}
        if source is None:
            source_id = int(
                conn.execute(
                    domain_sources.insert().values(
                        domain_id=domain_id,
                        provider=remote.provider,
                        external_id=remote.external_id,
                        lifecycle_status="active",
                        remote_status=remote_status,
                        metadata_json=remote.metadata,
                        created_at=timestamp,
                        updated_at=timestamp,
                        last_seen_at=timestamp,
                        last_sync_run_id=run_id,
                    )
                ).inserted_primary_key[0]
            )
            self._history(conn, domain_id, source_id, run_id, "created", None, current)
        else:
            source_id = int(source["id"])
            before = {
                "remote_status": source["remote_status"],
                "metadata": json_value(source["metadata_json"]),
                "lifecycle_status": source["lifecycle_status"],
            }
            changed = before != current
            values: dict[str, Any] = {
                "domain_id": domain_id,
                "lifecycle_status": "active",
                "remote_status": remote_status,
                "metadata_json": remote.metadata,
                "last_seen_at": timestamp,
                "last_sync_run_id": run_id,
                "archived_at": None,
            }
            if changed:
                values["updated_at"] = timestamp
            conn.execute(domain_sources.update().where(domain_sources.c.id == source_id).values(**values))
            if changed:
                self._history(
                    conn,
                    domain_id,
                    source_id,
                    run_id,
                    "restored" if before["lifecycle_status"] == "archived" else "updated",
                    before,
                    current,
                )
        self._snapshot(conn, source_id, run_id, current, timestamp)
        self._refresh_domain(conn, domain_id, run_id, timestamp)

    def _archive_missing_sources(self, conn: Connection, run_id: int, provider: str) -> int:
        rows = conn.execute(
            select(domain_sources).where(
                domain_sources.c.provider == provider,
                domain_sources.c.lifecycle_status == "active",
                (domain_sources.c.last_sync_run_id.is_(None)) | (domain_sources.c.last_sync_run_id != run_id),
            )
        ).mappings().all()
        timestamp = now()
        affected_domains: set[int] = set()
        for source in rows:
            before = {
                "remote_status": source["remote_status"],
                "metadata": json_value(source["metadata_json"]),
                "lifecycle_status": "active",
            }
            after = {**before, "lifecycle_status": "archived"}
            conn.execute(
                domain_sources.update()
                .where(domain_sources.c.id == source["id"])
                .values(lifecycle_status="archived", archived_at=timestamp, updated_at=timestamp)
            )
            self._history(conn, int(source["domain_id"]), int(source["id"]), run_id, "archived", before, after)
            self._snapshot(conn, int(source["id"]), run_id, after, timestamp)
            affected_domains.add(int(source["domain_id"]))
        for domain_id in affected_domains:
            self._refresh_domain(conn, domain_id, run_id, timestamp)
        return len(rows)

    def _refresh_domain(self, conn: Connection, domain_id: int, run_id: int, timestamp: str) -> None:
        domain = conn.execute(select(domains).where(domains.c.id == domain_id)).mappings().one()
        active = conn.execute(
            select(domain_sources.c.id)
            .where(domain_sources.c.domain_id == domain_id, domain_sources.c.lifecycle_status == "active")
            .limit(1)
        ).scalar_one_or_none() is not None
        target = "active" if active else "archived"
        if domain["lifecycle_status"] == target:
            if target == "active":
                conn.execute(domains.update().where(domains.c.id == domain_id).values(last_seen_at=timestamp))
            return
        before = {"name": domain["name"], "lifecycle_status": domain["lifecycle_status"]}
        after = {"name": domain["name"], "lifecycle_status": target}
        conn.execute(
            domains.update()
            .where(domains.c.id == domain_id)
            .values(
                lifecycle_status=target,
                updated_at=timestamp,
                last_seen_at=timestamp if target == "active" else domain["last_seen_at"],
                archived_at=timestamp if target == "archived" else None,
            )
        )
        self._history(conn, domain_id, None, run_id, "restored" if target == "active" else "archived", before, after)

    @staticmethod
    def _snapshot(
        conn: Connection,
        source_id: int,
        run_id: int,
        state: dict[str, Any],
        timestamp: str,
    ) -> None:
        conn.execute(
            source_snapshots.insert().values(
                source_id=source_id,
                sync_run_id=run_id,
                remote_status=state["remote_status"],
                lifecycle_status=state["lifecycle_status"],
                metadata_json=state["metadata"],
                captured_at=timestamp,
            )
        )

    @staticmethod
    def _history(
        conn: Connection,
        domain_id: int,
        source_id: int | None,
        run_id: int | None,
        event_type: str,
        before: Any,
        after: Any,
    ) -> None:
        conn.execute(
            history.insert().values(
                domain_id=domain_id,
                source_id=source_id,
                sync_run_id=run_id,
                event_type=event_type,
                before_json=before,
                after_json=after,
                occurred_at=now(),
            )
        )
