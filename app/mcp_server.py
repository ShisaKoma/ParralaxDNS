"""Read-only MCP tools for the Parralax-DNS inventory.

The HTTP transport and its authentication wrapper are mounted by ``app.main``.
Keeping the tool implementation separate from the FastAPI routes makes the MCP
contract explicit and prevents it from becoming a generic proxy to the REST API.
"""

from __future__ import annotations

from collections.abc import Callable
import os
import secrets
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from starlette.responses import JSONResponse, PlainTextResponse

from .comparison import compare, compare_source_snapshots, records_from_metadata
from .database import Database
from .providers import ProviderError


READ_ONLY = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)


def _environment_values(name: str, default: str) -> list[str]:
    """Read a comma-separated allow-list without accepting empty entries."""
    raw = os.getenv(name, default)
    return [value.strip() for value in raw.split(",") if value.strip()]


def _transport_security() -> TransportSecuritySettings:
    return TransportSecuritySettings(
        allowed_hosts=_environment_values(
            "PARRALAX_MCP_ALLOWED_HOSTS",
            "localhost,localhost:*,127.0.0.1,127.0.0.1:*",
        ),
        allowed_origins=_environment_values(
            "PARRALAX_MCP_ALLOWED_ORIGINS",
            "http://localhost:*,http://127.0.0.1:*",
        ),
    )


class BearerProtectedMcpApplication:
    """Require an application-owned bearer token before MCP initialization.

    FastMCP handles the protocol after this boundary. Keeping this check at the
    ASGI edge also ensures an unauthenticated caller cannot discover tools.
    """

    def __init__(self, application: Any):
        self.application = application

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http" or scope.get("path") != "/mcp":
            await self.application(scope, receive, send)
            return

        expected_token = os.getenv("PARRALAX_MCP_TOKEN")
        if not expected_token:
            await PlainTextResponse("Not Found", status_code=404)(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        authorization = headers.get(b"authorization", b"").decode("latin-1")
        scheme, separator, supplied_token = authorization.partition(" ")
        if (
            scheme.lower() != "bearer"
            or not separator
            or not supplied_token
            or not secrets.compare_digest(supplied_token, expected_token)
        ):
            await JSONResponse(
                {"detail": "Authentification MCP requise."},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )(scope, receive, send)
            return
        await self.application(scope, receive, send)


def protected_mcp_application(server: FastMCP) -> BearerProtectedMcpApplication:
    """Build the authenticated ASGI app after creating its session manager."""
    return BearerProtectedMcpApplication(server.streamable_http_app())


def _bounded(value: int, *, name: str, minimum: int, maximum: int) -> int:
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} doit être compris entre {minimum} et {maximum}.")
    return value


def _source_summary(source: dict[str, Any]) -> dict[str, Any]:
    """Return inventory facts without raw provider metadata."""
    return {
        "id": source["id"],
        "provider": source["provider"],
        "external_id": source["external_id"],
        "lifecycle_status": source["lifecycle_status"],
        "remote_status": source.get("remote_status"),
        "created_at": source.get("created_at"),
        "updated_at": source.get("updated_at"),
        "last_seen_at": source.get("last_seen_at"),
        "archived_at": source.get("archived_at"),
    }


def _domain_summary(domain: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": domain["id"],
        "name": domain["name"],
        "lifecycle_status": domain["lifecycle_status"],
        "created_at": domain.get("created_at"),
        "updated_at": domain.get("updated_at"),
        "last_seen_at": domain.get("last_seen_at"),
        "archived_at": domain.get("archived_at"),
        "sources": [_source_summary(source) for source in domain["sources"]],
    }


def _history_summary(entry: dict[str, Any]) -> dict[str, Any]:
    """Expose the audit trail without before/after metadata payloads."""
    return {
        "id": entry["id"],
        "event_type": entry["event_type"],
        "occurred_at": entry["occurred_at"],
        "source_id": entry.get("source_id"),
        "sync_run_id": entry.get("sync_run_id"),
    }


def _compare_domain_sources(
    database: Database,
    providers: Callable[[], list[Any]],
    domain_id: int,
    record_limit: int,
) -> dict[str, Any]:
    """Reproduce the safe, read-only comparison used by the web application."""
    domain = database.get_domain(domain_id)
    if domain is None:
        return {"status": "not_found", "message": "Domaine introuvable."}

    configured = {provider.name: provider for provider in providers()}
    records_by_source: dict[str, list[dict[str, Any]]] = {}
    errors: dict[str, str] = {}
    for source in domain["sources"]:
        source_key = f"{source['provider']}:{source['external_id']}"
        if source["provider"].startswith(("windows_dns:", "custom:")):
            records_by_source[source_key] = records_from_metadata(source["metadata"])
            continue

        provider = configured.get(source["provider"])
        fetch_records = getattr(provider, "list_dns_records", None) if provider else None
        if not callable(fetch_records):
            errors[source_key] = f"La source {source['provider']} ne fournit pas de lecture DNS."
            continue
        try:
            lookup_key = source["external_id"] if source["provider"] == "cloudflare" else domain["name"]
            records_by_source[source_key] = fetch_records(lookup_key)
        except ProviderError as exc:
            errors[source_key] = str(exc)

    comparison = compare(domain, records_by_source, errors)
    dns = comparison["dns"]
    truncated = False
    if len(dns["common_records"]) > record_limit:
        dns["common_records"] = dns["common_records"][:record_limit]
        truncated = True
    for source_key, records in dns["only_by_source"].items():
        if len(records) > record_limit:
            dns["only_by_source"][source_key] = records[:record_limit]
            truncated = True
    if len(dns["conflicts"]) > record_limit:
        dns["conflicts"] = dns["conflicts"][:record_limit]
        truncated = True
    comparison["result_limit"] = record_limit
    comparison["truncated"] = truncated
    return {"status": "success", "comparison": comparison}


def _bounded_snapshot_comparison(comparison: dict[str, Any], record_limit: int) -> dict[str, Any]:
    """Keep historical DNS changes useful without returning raw source metadata."""
    records = comparison["records"]
    truncated = False
    for key in ("added", "removed", "changed"):
        if len(records[key]) > record_limit:
            records[key] = records[key][:record_limit]
            truncated = True
    for change in records["changed"]:
        for key in ("before", "after"):
            if len(change[key]) > record_limit:
                change[key] = change[key][:record_limit]
                truncated = True

    # The comparison helper operates on full source snapshots. Source metadata
    # can contain provider-specific private data, so expose only the fact that
    # a configuration field changed, never its previous or new raw value.
    comparison["configuration_fields_changed"] = [
        change["field"] for change in comparison.pop("configuration_changes")
    ]
    comparison["result_limit"] = record_limit
    comparison["truncated"] = truncated
    return comparison


def create_mcp_server(
    database: Callable[[], Database],
    providers: Callable[[], list[Any]],
) -> FastMCP:
    """Create the connector without retaining a stale database in tests."""
    server = FastMCP(
        "parralax-dns",
        instructions=(
            "Parralax-DNS fournit un inventaire DNS en lecture seule. Utilisez "
            "list_domains pour rechercher un domaine, puis get_domain avec son ID. "
            "Les outils ne déclenchent jamais de synchronisation, de clonage ou "
            "de modification chez un fournisseur DNS."
        ),
        streamable_http_path="/mcp",
        json_response=True,
        transport_security=_transport_security(),
    )

    @server.tool(
        title="Lister les domaines DNS",
        description=(
            "Recherche dans l'inventaire Parralax-DNS. Utiliser avant get_domain "
            "lorsque l'ID du domaine n'est pas connu."
        ),
        annotations=READ_ONLY,
    )
    def list_domains(
        query: str | None = None,
        include_archived: bool = False,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        """List a bounded, metadata-free page of inventoried domains."""
        _bounded(offset, name="offset", minimum=0, maximum=10_000)
        _bounded(limit, name="limit", minimum=1, maximum=200)
        normalized_query = query.strip().casefold() if query else ""
        if len(normalized_query) > 253:
            raise ValueError("query ne peut pas dépasser 253 caractères.")

        items = database().list_domains(include_archived=include_archived)
        if normalized_query:
            items = [
                item
                for item in items
                if normalized_query in item["name"].casefold()
                or any(normalized_query in source["provider"].casefold() for source in item["sources"])
            ]
        return {
            "total": len(items),
            "offset": offset,
            "limit": limit,
            "domains": [_domain_summary(item) for item in items[offset : offset + limit]],
        }

    @server.tool(
        title="Lire un domaine DNS",
        description=(
            "Retourne le statut et les sources d'un domaine inventorié. Les "
            "métadonnées brutes des fournisseurs ne sont pas exposées."
        ),
        annotations=READ_ONLY,
    )
    def get_domain(domain_id: int) -> dict[str, Any]:
        """Read one domain and its provider sources by its stable inventory ID."""
        _bounded(domain_id, name="domain_id", minimum=1, maximum=2_147_483_647)
        domain = database().get_domain(domain_id)
        if domain is None:
            return {"status": "not_found", "message": "Domaine introuvable."}
        return {"status": "success", "domain": _domain_summary(domain)}

    @server.tool(
        title="Lire l'historique d'un domaine",
        description="Liste les derniers événements d'inventaire pour un domaine, sans métadonnées brutes.",
        annotations=READ_ONLY,
    )
    def get_domain_history(domain_id: int, limit: int = 50) -> dict[str, Any]:
        """Return a bounded audit trail for a known domain."""
        _bounded(domain_id, name="domain_id", minimum=1, maximum=2_147_483_647)
        _bounded(limit, name="limit", minimum=1, maximum=200)
        domain = database().get_domain(domain_id)
        if domain is None:
            return {"status": "not_found", "message": "Domaine introuvable."}
        return {
            "status": "success",
            "domain": {"id": domain["id"], "name": domain["name"]},
            "events": [_history_summary(entry) for entry in domain["history"][:limit]],
        }

    @server.tool(
        title="Comparer les sources DNS d'un domaine",
        description=(
            "Compare la configuration DNS actuellement disponible entre les sources "
            "d'un domaine. Peut relire les API DNS déjà configurées, sans les modifier."
        ),
        annotations=READ_ONLY,
    )
    def compare_domain_sources(domain_id: int, record_limit: int = 100) -> dict[str, Any]:
        """Compare DNS records across all sources of a domain."""
        _bounded(domain_id, name="domain_id", minimum=1, maximum=2_147_483_647)
        _bounded(record_limit, name="record_limit", minimum=1, maximum=200)
        return _compare_domain_sources(database(), providers, domain_id, record_limit)

    @server.tool(
        title="Lister les instantanés d'une source DNS",
        description=(
            "Liste les synchronisations réussies disponibles pour une source, afin de "
            "choisir deux IDs à comparer."
        ),
        annotations=READ_ONLY,
    )
    def list_source_snapshots(source_id: int, limit: int = 50) -> dict[str, Any]:
        """List timestamped snapshots without exposing their complete payload."""
        _bounded(source_id, name="source_id", minimum=1, maximum=2_147_483_647)
        _bounded(limit, name="limit", minimum=1, maximum=200)
        source = database().source(source_id)
        if source is None:
            return {"status": "not_found", "message": "Source introuvable."}
        snapshots = database().list_source_snapshots(source_id)
        return {
            "status": "success",
            "source": _source_summary(source),
            "snapshots": [
                {
                    "sync_run_id": snapshot["sync_run_id"],
                    "captured_at": snapshot["captured_at"],
                    "remote_status": snapshot.get("remote_status"),
                    "lifecycle_status": snapshot["lifecycle_status"],
                    "trigger": snapshot.get("trigger"),
                    "run_started_at": snapshot.get("run_started_at"),
                    "run_completed_at": snapshot.get("run_completed_at"),
                    "dns_record_count": len(records_from_metadata(snapshot["metadata"])),
                }
                for snapshot in snapshots[:limit]
            ],
        }

    @server.tool(
        title="Comparer deux instantanés DNS",
        description=(
            "Compare deux synchronisations réussies de la même source et retourne les "
            "records ajoutés, supprimés ou modifiés, ainsi que les noms des paramètres modifiés."
        ),
        annotations=READ_ONLY,
    )
    def compare_source_history(
        source_id: int,
        before_sync_run_id: int,
        after_sync_run_id: int,
        record_limit: int = 100,
    ) -> dict[str, Any]:
        """Compare two historical snapshots for one source."""
        _bounded(source_id, name="source_id", minimum=1, maximum=2_147_483_647)
        _bounded(before_sync_run_id, name="before_sync_run_id", minimum=1, maximum=2_147_483_647)
        _bounded(after_sync_run_id, name="after_sync_run_id", minimum=1, maximum=2_147_483_647)
        _bounded(record_limit, name="record_limit", minimum=1, maximum=200)
        if before_sync_run_id == after_sync_run_id:
            raise ValueError("Les deux synchronisations doivent être distinctes.")
        source = database().source(source_id)
        if source is None:
            return {"status": "not_found", "message": "Source introuvable."}
        before = database().source_snapshot(source_id, before_sync_run_id)
        after = database().source_snapshot(source_id, after_sync_run_id)
        if before is None or after is None:
            return {
                "status": "not_found",
                "message": "Un des instantanés demandés est introuvable pour cette source.",
            }
        return {
            "status": "success",
            "source": _source_summary(source),
            "before": {"sync_run_id": before["sync_run_id"], "captured_at": before["captured_at"]},
            "after": {"sync_run_id": after["sync_run_id"], "captured_at": after["captured_at"]},
            "comparison": _bounded_snapshot_comparison(
                compare_source_snapshots(
                    domain_name=source["domain_name"],
                    provider=source["provider"],
                    before=before["metadata"],
                    after=after["metadata"],
                ),
                record_limit,
            ),
        }

    return server
