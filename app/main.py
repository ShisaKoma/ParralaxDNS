from __future__ import annotations

import asyncio
import base64
import binascii
import json
import logging
import os
import secrets
import threading
import time
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import insert

from .comparison import compare, compare_source_snapshots
from .database import Database, history, now
from .mcp_server import create_mcp_server, protected_mcp_application
from .providers import (
    CloudflareProvider,
    CustomDnsProvider,
    InfomaniakProvider,
    NginxInstanceManagerProvider,
    OvhProvider,
    ProviderError,
    TechnitiumDnsProvider,
    WindowsDnsProvider,
)
from .sync import Synchronizer


DB = Database(os.getenv("DATABASE_URL") or os.getenv("DATABASE_PATH", "data/domain_inventory.sqlite3"))
API_PROVIDERS = ("cloudflare", "infomaniak", "ovh", "technitium", "nginx_nim")
API_DOCS_ENABLED = os.getenv("API_DOCS_ENABLED", "true").lower() in {"1", "true", "yes"}
LOGGER = logging.getLogger(__name__)
SYNC_EXECUTION_LOCK = threading.Lock()
SCHEDULE_STATE: dict[str, Any] = {
    "running": False,
    "last_started_at": None,
    "last_completed_at": None,
    "last_status": None,
    "next_run_at": None,
}
UI_AUTH_EXEMPT_PATHS = {
    "/healthz",
    "/mcp",  # MCP has its own Bearer credential and can carry only one Authorization header.
}
COLLECTOR_SYNC_PATHS = {
    "/api/collectors/windows-dns/sync",
    "/api/collectors/custom-dns/sync",
}
UI_CONTENT_SECURITY_POLICY = (
    "default-src 'self'; base-uri 'none'; connect-src 'self'; form-action 'self'; "
    "frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; "
    "script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
)


def ui_authentication_configuration() -> tuple[bytes, bytes] | None:
    """Return configured Basic credentials, or disable the optional UI protection.

    A partial configuration is an operational error: silently disabling the
    protection would expose the inventory after a typo in a deployment secret.
    """
    email = os.getenv("PARRALAX_UI_AUTH_EMAIL", "").strip()
    password = os.getenv("PARRALAX_UI_AUTH_PASSWORD", "")
    if not email and not password:
        return None
    if not email or not password:
        raise RuntimeError(
            "PARRALAX_UI_AUTH_EMAIL et PARRALAX_UI_AUTH_PASSWORD doivent être définis ensemble."
        )
    email_bytes = email.encode("utf-8")
    password_bytes = password.encode("utf-8")
    if len(email_bytes) > 253:
        raise RuntimeError("PARRALAX_UI_AUTH_EMAIL dépasse 253 octets.")
    # No MFA is present on this local shared account, so keep a deliberately
    # conservative minimum password length.
    if len(password) < 15:
        raise RuntimeError("PARRALAX_UI_AUTH_PASSWORD doit contenir au moins 15 caractères.")
    if len(password_bytes) > 1024:
        raise RuntimeError("PARRALAX_UI_AUTH_PASSWORD dépasse la taille autorisée.")
    return email_bytes, password_bytes


def valid_basic_authentication(authorization: str | None, expected: tuple[bytes, bytes]) -> bool:
    """Parse a bounded Basic header and compare both fields in constant time."""
    if not authorization or len(authorization) > 4096:
        return False
    scheme, separator, encoded = authorization.partition(" ")
    if scheme.lower() != "basic" or not separator or not encoded:
        return False
    try:
        decoded = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError, binascii.Error):
        return False
    if len(decoded) > 2048:
        return False
    email, separator, password = decoded.partition(b":")
    if not separator:
        return False
    expected_email, expected_password = expected
    return secrets.compare_digest(email, expected_email) and secrets.compare_digest(password, expected_password)


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Fail closed on an incomplete UI-auth configuration before serving data.
    ui_authentication_configuration()
    # Validate provider endpoints and TLS policy before the first request.
    configured_providers()
    DB.initialize()
    interval_minutes, run_on_startup = automatic_sync_configuration()
    SCHEDULE_STATE.update({
        "running": False,
        "last_started_at": None,
        "last_completed_at": None,
        "last_status": None,
        "next_run_at": None,
    })
    async with active_mcp_session():
        task = None
        if interval_minutes or run_on_startup:
            task = asyncio.create_task(automatic_sync_loop(interval_minutes, run_on_startup))
        try:
            yield
        finally:
            if task is not None:
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task


@asynccontextmanager
async def active_mcp_session():
    """Start the single-use MCP session manager only for an enabled endpoint."""
    if not os.getenv("PARRALAX_MCP_TOKEN"):
        yield
        return
    async with MCP_SERVER.session_manager.run():
        yield


app = FastAPI(
    title="Parralax-DNS API",
    summary="Inventaire, comparaison et historique DNS multi-sources.",
    description=(
        "Cette API pilote l'inventaire Parralax-DNS. Les opérations de lecture sont "
        "non destructives ; une synchronisation archive localement les ressources "
        "qui ne sont plus vues. Les collecteurs doivent utiliser HTTPS et un jeton "
        "dédié. Les sources personnalisées sont poussées avec "
        "`POST /api/collectors/custom-dns/sync`."
    ),
    version="0.3.0",
    openapi_tags=[
        {"name": "Inventaire", "description": "Domaines, sources et comparaison DNS."},
        {"name": "Historique", "description": "Journal append-only des changements, affiché sans métadonnées brutes."},
        {"name": "Synchronisation", "description": "Synchronisation des fournisseurs configurés."},
        {"name": "Diagnostics", "description": "Tests de connectivité rejouables, sans écriture chez les fournisseurs."},
        {"name": "Collecteurs", "description": "Inventaires poussés depuis Windows DNS, Plesk, cPanel ou une source interne."},
        {"name": "Zones", "description": "Export BIND Cloudflare et clonage explicite vers Infomaniak."},
    ],
    docs_url="/api/docs" if API_DOCS_ENABLED else None,
    redoc_url=None,
    openapi_url="/api/openapi.json" if API_DOCS_ENABLED else None,
    lifespan=lifespan,
)


@app.middleware("http")
async def protect_inventory_responses(request: Request, call_next):
    """Protect the browser UI/API when a shared local credential is configured."""
    path = request.url.path
    credentials = ui_authentication_configuration()
    has_dedicated_credential = (
        path in UI_AUTH_EXEMPT_PATHS
        or (request.method == "POST" and path in COLLECTOR_SYNC_PATHS)
    )
    if credentials and not has_dedicated_credential:
        if not valid_basic_authentication(request.headers.get("Authorization"), credentials):
            response = PlainTextResponse(
                "Authentification requise.",
                status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="Parralax-DNS", charset="UTF-8"'},
            )
        elif request.method not in {"GET", "HEAD", "OPTIONS"} and path.startswith("/api/") and (
            request.headers.get("X-Parralax-UI-Request") != "1"
        ):
            # A cross-site HTML form cannot set this custom header. The UI adds
            # it to every write request, which protects the shared Basic
            # credential from browser-based CSRF without sharing a token.
            response = PlainTextResponse("Requête d'interface invalide.", status_code=403)
        else:
            response = await call_next(request)
    else:
        response = await call_next(request)

    # The inventory can contain DNS topology and provider identifiers. Avoid
    # persisting it in browser/proxy caches and reduce common browser attacks.
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
    if path in {"/", "/history"}:
        response.headers.setdefault("Content-Security-Policy", UI_CONTENT_SECURITY_POLICY)
    return response


def configured_providers():
    providers = []
    if token := os.getenv("CLOUDFLARE_API_TOKEN"):
        providers.append(CloudflareProvider(token))
    if token := os.getenv("INFOMANIAK_API_TOKEN"):
        providers.append(InfomaniakProvider(token, os.getenv("INFOMANIAK_ACCOUNT_ID") or None))
    ovh_credentials = (
        os.getenv("OVH_APPLICATION_KEY"),
        os.getenv("OVH_APPLICATION_SECRET"),
        os.getenv("OVH_CONSUMER_KEY"),
    )
    if all(ovh_credentials):
        providers.append(OvhProvider(*ovh_credentials, base_url=os.getenv("OVH_API_BASE_URL", "https://eu.api.ovh.com/1.0").rstrip("/")))
    if technitium_url := os.getenv("TECHNITIUM_DNS_API_URL"):
        if technitium_token := os.getenv("TECHNITIUM_DNS_API_TOKEN"):
            providers.append(TechnitiumDnsProvider(
                base_url=technitium_url.rstrip("/"),
                token=technitium_token,
                node=os.getenv("TECHNITIUM_DNS_NODE") or None,
                verify_tls=os.getenv("TECHNITIUM_DNS_VERIFY_TLS", "true").lower() in {"1", "true", "yes"},
            ))
    if nim_url := os.getenv("NGINX_NIM_URL"):
        nim_token = os.getenv("NGINX_NIM_API_TOKEN") or None
        nim_username = os.getenv("NGINX_NIM_USERNAME") or None
        nim_password = os.getenv("NGINX_NIM_PASSWORD") or None
        if nim_token or (nim_username and nim_password):
            providers.append(NginxInstanceManagerProvider(
                base_url=nim_url.rstrip("/"),
                api_version=os.getenv("NGINX_NIM_API_VERSION", "v2"),
                bearer_token=nim_token,
                username=nim_username,
                password=nim_password,
                verify_tls=os.getenv("NGINX_NIM_VERIFY_TLS", "true").lower() in {"1", "true", "yes"},
            ))
    return providers


def automatic_sync_configuration() -> tuple[int, bool]:
    """Read a bounded interval. Zero disables the periodic loop."""
    raw_interval = os.getenv("SYNC_INTERVAL_MINUTES", "0").strip()
    try:
        interval_minutes = int(raw_interval)
    except ValueError as exc:
        raise RuntimeError("SYNC_INTERVAL_MINUTES doit être un entier compris entre 0 et 10080.") from exc
    if not 0 <= interval_minutes <= 10_080:
        raise RuntimeError("SYNC_INTERVAL_MINUTES doit être compris entre 0 et 10080.")
    run_on_startup = os.getenv("AUTO_SYNC_ON_STARTUP", "false").lower() in {"1", "true", "yes"}
    return interval_minutes, run_on_startup


def synchronize_configured_providers(*, trigger: str) -> dict[str, Any]:
    """Serialize manual and automatic API synchronizations in this process."""
    if not SYNC_EXECUTION_LOCK.acquire(blocking=False):
        return {
            "status": "skipped",
            "reason": "Une synchronisation est déjà en cours.",
            "results": [],
        }
    try:
        providers = configured_providers()
        if not providers:
            return {
                "status": "skipped",
                "reason": "Aucun connecteur API n'est configuré.",
                "results": [],
            }
        synchronizer = Synchronizer(DB)
        results = []
        for provider in providers:
            try:
                results.append(synchronizer.sync(provider, trigger=trigger))
            except ProviderError as exc:
                results.append({"provider": provider.name, "trigger": trigger, "status": "failed", "error": str(exc)})
            except Exception:
                LOGGER.exception("Erreur imprévue de synchronisation pour %s", provider.name)
                results.append({"provider": provider.name, "trigger": trigger, "status": "failed", "error": "Erreur interne pendant la synchronisation."})
        return {"status": "completed", "results": results}
    finally:
        SYNC_EXECUTION_LOCK.release()


async def run_scheduled_sync() -> None:
    """Run the blocking provider clients outside the web event loop."""
    SCHEDULE_STATE.update({"running": True, "last_started_at": now(), "next_run_at": None})
    try:
        result = await asyncio.to_thread(synchronize_configured_providers, trigger="scheduled")
        if result["status"] == "completed":
            state = "partial_failure" if any(item["status"] == "failed" for item in result["results"]) else "success"
        else:
            state = "skipped"
        SCHEDULE_STATE["last_status"] = state
    except Exception:  # pragma: no cover - prevents a scheduler task from dying unexpectedly.
        LOGGER.exception("La synchronisation automatique a échoué.")
        SCHEDULE_STATE["last_status"] = "failed"
    finally:
        SCHEDULE_STATE.update({"running": False, "last_completed_at": now()})


async def automatic_sync_loop(interval_minutes: int, run_on_startup: bool) -> None:
    if run_on_startup:
        await run_scheduled_sync()
    while interval_minutes:
        SCHEDULE_STATE["next_run_at"] = (
            datetime.now(timezone.utc) + timedelta(minutes=interval_minutes)
        ).isoformat(timespec="seconds")
        await asyncio.sleep(interval_minutes * 60)
        await run_scheduled_sync()


def response_preview(domains: list[Any]) -> dict[str, Any]:
    """A useful, bounded API response preview without raw provider metadata."""
    return {
        "kind": "domain_inventory",
        "domain_count": len(domains),
        "sample_domains": [
            {
                "name": str(domain.name)[:253],
                "remote_status": str(domain.remote_status)[:120] if domain.remote_status is not None else None,
            }
            for domain in domains[:5]
        ],
    }


def run_connectivity_test(provider: Any) -> dict[str, Any]:
    """Run and persist a safe, read-only diagnostic for one configured API."""
    test_id = DB.start_connectivity_test(provider.name)
    started = time.perf_counter()
    try:
        domains = provider.list_domains()
    except ProviderError as exc:
        DB.finish_connectivity_test(
            test_id,
            status="failed",
            latency_ms=round((time.perf_counter() - started) * 1000),
            error_message=str(exc)[:500],
        )
    except Exception:
        # Do not persist unexpected exception details: they can contain sensitive
        # implementation or configuration data.
        DB.finish_connectivity_test(
            test_id,
            status="failed",
            latency_ms=round((time.perf_counter() - started) * 1000),
            error_message="Erreur interne pendant le test du connecteur.",
        )
    else:
        DB.finish_connectivity_test(
            test_id,
            status="success",
            latency_ms=round((time.perf_counter() - started) * 1000),
            preview=response_preview(domains),
        )
    result = DB.connectivity_test(test_id)
    if result is None:  # pragma: no cover - protects against a damaged database.
        raise HTTPException(500, "Résultat de test introuvable.")
    return result


class CloneRequest(BaseModel):
    target_zone: str = Field(pattern=r"^[A-Za-z0-9.-]+$")


class WindowsDnsRecord(BaseModel):
    name: str
    type: str
    value: str
    ttl: int | None = None


class WindowsDnsZone(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9._-]+$")
    zone_type: str | None = None
    is_ds_integrated: bool | None = None
    dynamic_update: str | None = None
    policies: list[dict] = Field(default_factory=list)
    records: list[WindowsDnsRecord] = Field(default_factory=list)


class WindowsDnsSyncRequest(BaseModel):
    server: str = Field(pattern=r"^[A-Za-z0-9._-]+$")
    zones: list[WindowsDnsZone]


class CustomDnsRecord(BaseModel):
    """Provider-neutral DNS record accepted from a source that pushes its inventory."""

    name: str = Field(min_length=1, max_length=253, description="Propriétaire du record (`@`, relatif ou FQDN).")
    type: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9-]{0,15}$", description="Type DNS, par exemple A, AAAA, CNAME, MX, TXT ou SRV.")
    value: str = Field(min_length=1, max_length=8192, description="Valeur ou cible du record.")
    ttl: int | None = Field(default=None, ge=0, le=2_147_483_647, description="TTL en secondes.")
    priority: int | None = Field(default=None, ge=0, le=65535, description="Priorité MX/SRV, si applicable.")
    weight: int | None = Field(default=None, ge=0, le=65535, description="Poids SRV, si applicable.")
    port: int | None = Field(default=None, ge=0, le=65535, description="Port SRV, si applicable.")
    model_config = ConfigDict(json_schema_extra={"example": {"name": "www", "type": "A", "value": "192.0.2.42", "ttl": 300}})


class CustomDnsZone(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9._-]+$", description="Nom de la zone DNS.")
    external_id: str | None = Field(default=None, max_length=512, description="Identifiant stable de la zone dans la source, si disponible.")
    remote_status: str | None = Field(default=None, max_length=512, description="État indiqué par la source (facultatif).")
    zone_type: str | None = Field(default=None, max_length=64, description="Type de zone indiqué par la source (facultatif).")
    records: list[CustomDnsRecord] = Field(default_factory=list, max_length=10_000)


class CustomDnsSyncRequest(BaseModel):
    source: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", description="Identifiant configuré de la source, par exemple `plesk-prod-01`.")
    zones: list[CustomDnsZone] = Field(max_length=10_000)
    model_config = ConfigDict(json_schema_extra={"example": {
        "source": "plesk-prod-01",
        "zones": [{
            "name": "example.org",
            "external_id": "plesk-zone-42",
            "remote_status": "active",
            "records": [
                {"name": "@", "type": "MX", "value": "mail.example.org", "priority": 10, "ttl": 3600},
                {"name": "www", "type": "A", "value": "192.0.2.42", "ttl": 300},
            ],
        }],
    }})


def configured_custom_dns_tokens() -> dict[str, str]:
    """Load source-specific collector tokens without ever persisting them."""
    raw_tokens = os.getenv("CUSTOM_DNS_COLLECTOR_TOKENS", "")
    if not raw_tokens:
        return {}
    try:
        configured = json.loads(raw_tokens)
    except json.JSONDecodeError as exc:
        raise HTTPException(503, "CUSTOM_DNS_COLLECTOR_TOKENS doit contenir un objet JSON valide.") from exc
    if not isinstance(configured, dict):
        raise HTTPException(503, "CUSTOM_DNS_COLLECTOR_TOKENS doit associer une source à un jeton.")
    tokens = {
        str(source).strip().lower(): token
        for source, token in configured.items()
        if isinstance(source, str) and isinstance(token, str) and token
    }
    if not tokens:
        raise HTTPException(503, "Aucun jeton de source personnalisée valide n'est configuré.")
    return tokens


def safe_history_entry(item: dict[str, Any]) -> dict[str, Any]:
    """Keep the UI audit trail useful without returning stored raw metadata."""
    before = item.get("before") if isinstance(item.get("before"), dict) else {}
    after = item.get("after") if isinstance(item.get("after"), dict) else {}
    event_type = item["event_type"]
    source = None
    if item.get("source_provider"):
        source = f"{item['source_provider']}:{item.get('source_external_id') or '—'}"
    if event_type == "zone_cloned":
        summary = f"Zone clonée vers {after.get('target_zone') or 'Infomaniak'}."
    elif event_type == "created":
        summary = "Source découverte." if source else "Domaine découvert."
    elif event_type == "updated":
        changed_fields = sorted(key for key in set(before) | set(after) if before.get(key) != after.get(key))
        summary = "Mise à jour de la source" + (f" ({', '.join(changed_fields[:4])})" if changed_fields else "") + "."
    elif event_type == "archived":
        summary = "Élément archivé après une collecte réussie."
    elif event_type == "restored":
        summary = "Élément restauré par une collecte réussie."
    else:  # pragma: no cover - schema constraint protects this branch.
        summary = "Événement enregistré."
    return {
        "id": item["id"],
        "domain_id": item["domain_id"],
        "domain_name": item["domain_name"],
        "source": source,
        "event_type": event_type,
        "trigger": item.get("trigger"),
        "occurred_at": item["occurred_at"],
        "summary": summary,
    }


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def home() -> str:
    return HTML.replace("{{DOCUMENTATION_LINK}}", DOCUMENTATION_LINK)


@app.get("/history", response_class=HTMLResponse, include_in_schema=False)
def history_page() -> str:
    return HISTORY_HTML.replace("{{DOCUMENTATION_LINK}}", DOCUMENTATION_LINK)


COLLECTOR_DOWNLOADS = {
    "plesk": "plesk-collector/collect-plesk-dns.sh",
    "windows": "collectors/windows-dns/Sync-ParralaxDns.ps1",
}


@app.get("/collectors/download/{collector}", include_in_schema=False)
def download_collector(collector: str):
    relative_path = COLLECTOR_DOWNLOADS.get(collector)
    if relative_path is None:
        raise HTTPException(404, "Collecteur introuvable.")
    path = Path(__file__).resolve().parent.parent / relative_path
    if not path.is_file():
        raise HTTPException(404, "Script absent de cette installation. Consultez le dépôt Parralax-DNS.")
    return FileResponse(path, filename=path.name, media_type="application/octet-stream")


@app.get("/favicon.ico", include_in_schema=False, status_code=204)
def favicon() -> Response:
    return Response(status_code=204)


@app.get("/healthz", include_in_schema=False)
def healthz():
    """Unauthenticated liveness endpoint with no inventory or configuration data."""
    return {"status": "ok"}


@app.get("/api/connectivity-tests", tags=["Diagnostics"], summary="Lire l'état des tests de connectivité")
def connectivity_tests():
    configured = {provider.name for provider in configured_providers()}
    history = DB.list_connectivity_tests()
    latest_by_provider = {}
    for test in history:
        latest_by_provider.setdefault(test["provider"], test)
    return {
        "providers": [
            {
                "provider": provider,
                "configured": provider in configured,
                "last_test": latest_by_provider.get(provider),
            }
            for provider in API_PROVIDERS
        ],
        "history": history,
        "windows_dns_note": "Les serveurs Windows DNS envoient leur collecte vers Parralax-DNS ; leur connectivité se teste depuis le collecteur PowerShell.",
    }


@app.post("/api/connectivity-tests", tags=["Diagnostics"], summary="Tester tous les connecteurs configurés")
def test_all_connectivity(
    ui_request: Annotated[str | None, Header(alias="X-Parralax-UI-Request")] = None,
):
    return {"results": [run_connectivity_test(provider) for provider in configured_providers()]}


@app.post("/api/connectivity-tests/{provider_name}/rerun", tags=["Diagnostics"], summary="Rejouer le test d'un connecteur")
def rerun_connectivity_test(
    provider_name: str,
    ui_request: Annotated[str | None, Header(alias="X-Parralax-UI-Request")] = None,
):
    providers = {provider.name: provider for provider in configured_providers()}
    provider = providers.get(provider_name)
    if provider is None:
        raise HTTPException(404, "Ce connecteur n'est pas configuré.")
    return run_connectivity_test(provider)


@app.get("/api/domains", tags=["Inventaire"], summary="Lister les domaines inventoriés")
def domains(include_archived: bool = False):
    return DB.list_domains(include_archived)


@app.get("/api/domains/{domain_id}", tags=["Inventaire"], summary="Lire un domaine, ses sources et son historique brut")
def domain(domain_id: int):
    item = DB.get_domain(domain_id)
    if not item:
        raise HTTPException(404, "Domaine introuvable")
    return item


@app.get("/api/domains/{domain_id}/comparison", tags=["Inventaire"], summary="Comparer les sources et les records DNS d'un domaine")
def compare_domain(domain_id: int):
    item = DB.get_domain(domain_id)
    if not item:
        raise HTTPException(404, "Domaine introuvable")
    providers = {provider.name: provider for provider in configured_providers()}
    records_by_source: dict[str, list[dict]] = {}
    errors: dict[str, str] = {}
    for source in item["sources"]:
        source_key = f"{source['provider']}:{source['external_id']}"
        if source["provider"].startswith(("windows_dns:", "custom:")):
            records_by_source[source_key] = source["metadata"].get("records", [])
            continue
        provider = providers.get(source["provider"])
        if not provider:
            errors[source_key] = f"Connecteur {source['provider']} non configuré."
            continue
        fetch_records = getattr(provider, "list_dns_records", None)
        if not callable(fetch_records):
            errors[source_key] = f"La source {source['provider']} n'est pas une source DNS."
            continue
        try:
            if source["provider"] == "cloudflare":
                records_by_source[source_key] = fetch_records(source["external_id"])
            else:
                records_by_source[source_key] = fetch_records(item["name"])
        except ProviderError as exc:
            errors[source_key] = str(exc)
    return compare(item, records_by_source, errors)


@app.get("/api/sources/{source_id}/snapshots", tags=["Historique"], summary="Lister les instantanés de synchronisation d'une source")
def source_snapshots(source_id: int):
    source = DB.source(source_id)
    if not source:
        raise HTTPException(404, "Source introuvable")
    return {
        "source": source,
        "snapshots": DB.list_source_snapshots(source_id),
    }


@app.get(
    "/api/sources/{source_id}/snapshots/compare",
    tags=["Historique"],
    summary="Comparer deux synchronisations d'une même source",
)
def compare_source_snapshot_runs(
    source_id: int,
    before_run_id: Annotated[int, Query(ge=1)],
    after_run_id: Annotated[int, Query(ge=1)],
):
    source = DB.source(source_id)
    if not source:
        raise HTTPException(404, "Source introuvable")
    before = DB.source_snapshot(source_id, before_run_id)
    after = DB.source_snapshot(source_id, after_run_id)
    if not before or not after:
        raise HTTPException(404, "Un des instantanés demandés est introuvable pour cette source")
    return {
        "source": {"id": source["id"], "provider": source["provider"], "external_id": source["external_id"]},
        "before": before,
        "after": after,
        "comparison": compare_source_snapshots(
            domain_name=source["domain_name"],
            provider=source["provider"],
            before=before["metadata"],
            after=after["metadata"],
        ),
    }


@app.get("/api/history", tags=["Historique"], summary="Lire l'historique inter-domaines affichable")
def history_feed(limit: Annotated[int, Query(ge=1, le=200)] = 100):
    return [safe_history_entry(item) for item in DB.list_history(limit)]


@app.post("/api/collectors/windows-dns/sync", tags=["Collecteurs"], summary="Recevoir l'inventaire d'un serveur Windows DNS")
def sync_windows_dns(
    payload: WindowsDnsSyncRequest,
    collector_token: Annotated[str | None, Header(alias="X-Parralax-Collector-Token")] = None,
):
    expected_token = os.getenv("WINDOWS_DNS_COLLECTOR_TOKEN")
    if not expected_token:
        raise HTTPException(503, "WINDOWS_DNS_COLLECTOR_TOKEN n'est pas configuré.")
    if not collector_token or not secrets.compare_digest(collector_token, expected_token):
        raise HTTPException(401, "Jeton du collecteur Windows DNS invalide.")
    provider = WindowsDnsProvider(payload.server, [zone.model_dump() for zone in payload.zones])
    return Synchronizer(DB).sync(provider, trigger="collector")


@app.post(
    "/api/collectors/custom-dns/sync",
    tags=["Collecteurs"],
    summary="Recevoir l'inventaire DNS d'une source personnalisée",
    description=(
        "Pour Plesk, cPanel ou une intégration interne. Configurez un jeton distinct "
        "pour chaque identifiant `source` dans `CUSTOM_DNS_COLLECTOR_TOKENS`, puis "
        "envoyez-le dans `X-Parralax-Source-Token`. Une collecte complète archive uniquement "
        "les zones absentes de cette même source."
    ),
)
def sync_custom_dns(
    payload: CustomDnsSyncRequest,
    source_token: Annotated[str | None, Header(alias="X-Parralax-Source-Token")] = None,
):
    tokens = configured_custom_dns_tokens()
    source_name = payload.source.strip().lower()
    expected_token = tokens.get(source_name)
    if not source_token or not expected_token or not secrets.compare_digest(source_token, expected_token):
        raise HTTPException(401, "Source personnalisée ou jeton invalide.")
    provider = CustomDnsProvider(source_name, [zone.model_dump() for zone in payload.zones])
    return Synchronizer(DB).sync(provider, trigger="collector")


@app.get("/api/sync-schedule", tags=["Synchronisation"], summary="Lire l'état de la synchronisation automatique")
def sync_schedule():
    interval_minutes, run_on_startup = automatic_sync_configuration()
    return {
        "interval_minutes": interval_minutes,
        "run_on_startup": run_on_startup,
        "enabled": bool(interval_minutes or run_on_startup),
        **SCHEDULE_STATE,
    }


@app.post("/api/sync", tags=["Synchronisation"], summary="Synchroniser les fournisseurs API configurés")
def sync(
    ui_request: Annotated[str | None, Header(alias="X-Parralax-UI-Request")] = None,
):
    result = synchronize_configured_providers(trigger="manual")
    if result["status"] == "skipped":
        status_code = 409 if result["reason"] == "Une synchronisation est déjà en cours." else 400
        raise HTTPException(status_code, result["reason"])
    return {"results": result["results"]}


def cloudflare_source(source_id: int):
    source = DB.source(source_id)
    if not source:
        raise HTTPException(404, "Source introuvable")
    if source["provider"] != "cloudflare":
        raise HTTPException(400, "Seules les zones Cloudflare ont un export BIND direct.")
    token = os.getenv("CLOUDFLARE_API_TOKEN")
    if not token:
        raise HTTPException(400, "CLOUDFLARE_API_TOKEN n'est pas configuré.")
    return source, CloudflareProvider(token)


@app.get("/api/sources/{source_id}/zone-file", response_class=PlainTextResponse, tags=["Zones"], summary="Télécharger l'export BIND d'une zone Cloudflare")
def zone_file(source_id: int):
    source, provider = cloudflare_source(source_id)
    try:
        zone = provider.export_zone_file(source["external_id"])
    except ProviderError as exc:
        raise HTTPException(502, str(exc)) from exc
    filename = f"{source['domain_name']}.zone"
    return PlainTextResponse(zone, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@app.post("/api/sources/{source_id}/clone-to-infomaniak", tags=["Zones"], summary="Cloner une zone Cloudflare vers Infomaniak")
def clone_to_infomaniak(
    source_id: int,
    payload: CloneRequest,
    ui_request: Annotated[str | None, Header(alias="X-Parralax-UI-Request")] = None,
):
    source, cloudflare = cloudflare_source(source_id)
    token = os.getenv("INFOMANIAK_API_TOKEN")
    if not token:
        raise HTTPException(400, "INFOMANIAK_API_TOKEN (avec dns:write) est requis pour le clonage.")
    try:
        raw_zone = cloudflare.export_zone_file(source["external_id"])
        result = InfomaniakProvider(token).create_zone_from_raw(payload.target_zone.rstrip(".").lower(), raw_zone)
    except ProviderError as exc:
        raise HTTPException(502, str(exc)) from exc
    with DB.connection() as conn:
        conn.execute(
            insert(history).values(
                domain_id=source["domain_id"],
                source_id=source_id,
                event_type="zone_cloned",
                after_json={"target_zone": payload.target_zone},
                occurred_at=now(),
            )
        )
    return {"status": "success", "target_zone": payload.target_zone, "infomaniak_zone": result}


# The MCP mount comes after the REST routes so it cannot shadow the application
# UI or API. Its session manager is started in the shared FastAPI lifespan.
MCP_SERVER = create_mcp_server(lambda: DB, configured_providers)
app.mount("/", protected_mcp_application(MCP_SERVER))


HTML = r'''<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Parralax-DNS</title>
<style>
:root { color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, sans-serif; color: #182231; background: #f5f7fa; }
body { margin: 0; } main { max-width: 1100px; margin: 48px auto; padding: 0 24px; }
h1 { margin: 0; font-size: 2rem; } .sub { color: #637083; margin: 8px 0 26px; }
.toolbar { display:flex; gap:12px; align-items:center; margin-bottom:20px; flex-wrap:wrap; } button { border:0; border-radius:8px; padding:10px 16px; background:#135fca; color:white; font-weight:650; cursor:pointer; } button:disabled{background:#e8edf3;color:#687587;cursor:not-allowed}.nav-link{display:inline-block;border:1px solid #cdd8e5;border-radius:8px;padding:9px 14px;background:#fff;color:#135fca;font-weight:650;text-decoration:none} label{font-size:.9rem} #message{font-size:.9rem;color:#4a5b70}
table { width:100%; border-collapse:collapse; background:#fff; border:1px solid #e0e6ed; border-radius:12px; overflow:hidden; } th,td { padding:13px 14px; border-bottom:1px solid #e9edf2; text-align:left; vertical-align:top; } th { color:#556577; font-size:.78rem; text-transform:uppercase; letter-spacing:.04em; background:#fafbfd; } tr:last-child td{border-bottom:0}.badge{display:inline-block;padding:3px 8px;border-radius:99px;background:#e7f7eb;color:#196638;font-size:.78rem;font-weight:700}.archived{background:#f1eef2;color:#735e75}.source{margin:0 0 5px}.muted{color:#637083;font-size:.86rem}.actions a{color:#135fca;font-size:.86rem}.empty{padding:32px;background:white;border:1px dashed #c8d1dc;border-radius:12px;color:#637083}.comparison{margin-top:24px;padding:20px;background:#fff;border:1px solid #dce5ef;border-radius:12px}.comparison h2{margin:0 0 12px;font-size:1.15rem}.comparison h3{margin:18px 0 7px;font-size:1rem}.profiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:10px}.profile{background:#f7f9fc;border-radius:8px;padding:12px}.profile dt{font-size:.78rem;color:#637083;margin-top:7px}.profile dd{margin:1px 0;word-break:break-word}.warning{color:#9e4b00}.records{margin:6px 0;padding-left:20px;font-family:ui-monospace,SFMono-Regular,monospace;font-size:.82rem}.close{float:right;background:#e8edf3;color:#314154;padding:6px 10px}
.schedule,.connectivity{margin:0 0 24px;padding:20px;background:#fff;border:1px solid #dce5ef;border-radius:12px}.schedule h2,.connectivity h2{font-size:1.1rem;margin:0 0 5px}.schedule p{margin:6px 0}.connector-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:10px;margin-top:14px}.connector{border:1px solid #e1e7ef;border-radius:9px;padding:13px}.connector header{display:flex;justify-content:space-between;align-items:center;gap:8px}.connector h3{margin:0;font-size:1rem}.connector button{padding:6px 9px;font-size:.8rem}.connector pre{margin:10px 0 0;padding:10px;max-height:180px;overflow:auto;background:#f6f8fb;border-radius:6px;font-size:.75rem;white-space:pre-wrap;word-break:break-word}.status-failed{background:#fff1eb;color:#a33d10}.status-pending{background:#edf1f5;color:#526274}.notice{margin:0;color:#637083;font-size:.86rem}

[hidden]{display:none!important} button:focus-visible,a:focus-visible,summary:focus-visible,input:focus-visible,select:focus-visible{outline:3px solid #79aaf1;outline-offset:3px}
.page-header{display:flex;justify-content:space-between;gap:24px;align-items:flex-start}.eyebrow{text-transform:uppercase;letter-spacing:.12em;font-size:.72rem;font-weight:750;color:#135fca;margin:0 0 8px}.secondary{background:#fff;color:#135fca;border:1px solid #cdd8e5}.tools{position:relative}.tools summary{list-style:none;cursor:pointer;white-space:nowrap}.tools summary::-webkit-details-marker{display:none}.tools summary::after{content:' ▾'}.tools-popover{position:absolute;right:0;top:48px;width:220px;padding:8px;background:#fff;border:1px solid #dce5ef;border-radius:12px;box-shadow:0 12px 36px #18223120;z-index:2}.tools-popover button,.tools-popover a{display:block;width:100%;box-sizing:border-box;text-align:left;border:0;border-radius:6px;background:white;color:#314154;padding:12px;font:inherit;text-decoration:none}.tools-popover button:hover,.tools-popover a:hover{background:#f1f5fb}.inventory-head{display:flex;align-items:center;justify-content:space-between;gap:16px;margin:26px 0 14px}.inventory-head h2{font-size:1.1rem;margin:0}.toolbar{margin-bottom:8px}.sub{max-width:650px;line-height:1.6}.schedule{padding:12px 16px;background:transparent;margin:16px 0}.schedule summary{cursor:pointer;color:#526274;font-size:.86rem}.schedule h2{display:none}.actions{min-width:150px}.actions button{padding:7px 12px}.action-hint{display:block;font-size:.75rem;margin-top:7px;max-width:170px;color:#637083}.table-scroll{overflow-x:auto}.empty h3{color:#182231;margin-top:0}.empty p{line-height:1.6}.empty button{margin-top:8px}#message:empty{display:none}#message{display:block;margin:12px 0}dialog{box-sizing:border-box;border:1px solid #dce5ef;border-radius:18px;padding:28px;width:min(860px,calc(100% - 32px));max-height:90vh;overflow:auto;color:#182231;box-shadow:0 24px 80px #18223130}dialog::backdrop{background:#14223980}dialog h2{font-size:1.4rem;margin:4px 0 12px}.dialog-head{display:flex;justify-content:space-between;gap:20px;align-items:flex-start}.dialog-head{position:sticky;top:-28px;background:#fff;z-index:1;padding:12px 0}.dialog-head .close{float:none}.connectivity{border:0;padding:16px 0 0;margin:0}.intro{color:#526274;line-height:1.6}.setup-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.field{display:flex;flex-direction:column;gap:8px;font-weight:650}.field input,.field select{box-sizing:border-box;width:100%;padding:11px;border:1px solid #b9c7d7;border-radius:8px;background:white;color:#182231;font:inherit}.step{border-top:1px solid #e1e7ef;margin-top:24px;padding-top:20px}.step h3{font-size:1rem;margin:0 0 12px}.step p,.step li{font-size:.9rem;line-height:1.65}.step code{overflow-wrap:anywhere}.code-box{background:#f3f6fa;border-radius:8px;padding:14px;white-space:pre-wrap;overflow-wrap:anywhere;font-size:.8rem;max-height:240px;overflow:auto}.copy-row{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.copy-row button{padding:7px 12px}.callout{padding:12px 16px;background:#edf4ff;border-radius:8px;color:#304e76;font-size:.88rem;line-height:1.6}.setup-status{color:#526274;font-size:.85rem;min-height:1.4em}.steps-overview{font-size:.85rem;color:#526274;padding:12px 0;border-bottom:1px solid #e1e7ef}
@media(max-width:640px){main{margin:24px auto;padding:0 16px}h1{font-size:1.65rem}.page-header{gap:8px}.setup-grid{grid-template-columns:1fr}dialog{padding:20px}.dialog-head{top:-20px}.inventory-head{align-items:flex-start}.toolbar>button{flex:1}.nav-link{padding:9px 10px}th,td{padding:12px 10px}}
</style></head><body><main>
<header class="page-header"><div><p class="eyebrow">Vue d’ensemble</p><h1>Parralax-DNS</h1><p class="sub">Retrouvez vos domaines et comparez leurs sources DNS au même endroit.</p></div>
<details class="tools" id="tools"><summary class="nav-link">Outils</summary><nav class="tools-popover" aria-label="Outils"><button id="open-diagnostics">Diagnostics API</button><button onclick="openSetup()">Connecter un serveur</button><a href="/history">Historique</a>{{DOCUMENTATION_LINK}}</nav></details></header>
<div class="toolbar"><button onclick="openSetup()">Connecter un serveur</button><button class="secondary" id="sync">Synchroniser les API</button><a class="nav-link" href="/history">Historique</a></div>
<p class="notice">Plesk et Windows DNS envoient leurs données depuis leur propre collecteur.</p><p id="message" role="status"></p>
<details class="schedule"><summary>Planification des synchronisations API</summary><section id="schedule" aria-live="polite"></section></details>
<div class="inventory-head"><h2>Domaines <span class="muted" id="domain-count"></span></h2><label><input type="checkbox" id="archived"> Afficher les archivés</label></div>
<div id="content" class="table-scroll" aria-live="polite"></div><section id="comparison" aria-live="polite"></section>
<dialog id="diagnostics-dialog" aria-labelledby="diagnostics-title"><header class="dialog-head"><div><p class="eyebrow">Outils</p><h2 id="diagnostics-title">Diagnostics API</h2></div><button class="close" onclick="q('#diagnostics-dialog').close()">Fermer</button></header><button id="diagnostics">Tester les API configurées</button><p id="diagnostic-message" role="status"></p><section id="connectivity" class="connectivity" aria-live="polite"></section></dialog>
<dialog id="setup-dialog" aria-labelledby="setup-title"><header class="dialog-head"><div><p class="eyebrow">Nouvelle source externe</p><h2 id="setup-title">Connecter un serveur</h2></div><button class="close" onclick="q('#setup-dialog').close()">Fermer</button></header>
<p class="intro">Un collecteur installé sur votre serveur lit les zones DNS et les envoie à Parralax-DNS. Le même jeton secret doit être configuré dans Parralax-DNS et sur ce serveur.</p>
<p class="steps-overview">1. Créer le jeton → 2. L’activer dans Parralax-DNS → 3. Installer le collecteur → 4. Vérifier la collecte</p>
<form id="setup-form"><div class="setup-grid"><label class="field">Type de serveur<select id="collector-kind"><option value="plesk">Plesk sous Linux</option><option value="windows">Windows DNS</option></select></label><label class="field" id="source-field">Identifiant de la source<input id="collector-source" value="plesk-prod-01" required maxlength="128" pattern="[A-Za-z0-9][A-Za-z0-9._\-]{0,127}" aria-describedby="source-help"></label></div>
<p class="notice" id="source-help">Choisissez un identifiant unique par serveur Plesk, sans espaces (ex. plesk-prod-01).</p>
<p><label class="field">URL HTTPS de Parralax-DNS<input id="collector-url" type="url" placeholder="https://dns.votre-entreprise.fr" required aria-describedby="url-help"></label></p><p class="notice" id="url-help">L’adresse de cette application, accessible depuis le serveur à connecter.</p>
<section class="step"><h3>1. Créer un jeton de collecte</h3><p>Ce jeton autorise l’envoi vers Parralax-DNS. Vous n’avez pas de clé API Plesk ou Microsoft à créer.</p><button type="submit" id="generate-token">Générer le jeton et les instructions</button><p class="setup-status" id="setup-status" role="status"></p></section></form>
<div id="setup-instructions" hidden>
<p class="callout">Jeton généré dans votre navigateur, sans enregistrement automatique. Il sera actif après l’étape 2. Conservez-le dans un emplacement sûr avant de fermer cette fenêtre.</p>
<section class="step"><h3>2. Activer le jeton dans Parralax-DNS</h3><p id="server-help"></p><pre class="code-box" id="server-config"></pre><div class="copy-row"><button class="secondary" data-copy="server-config">Copier la configuration</button></div><p>Dans le fichier <code>.env</code> du déploiement Parralax-DNS, ajoutez ou mettez à jour cette variable. Avec Docker Compose, appliquez-la avec <code>docker compose up -d --force-recreate parralax-dns</code> (conservez vos options de déploiement habituelles). Pour un service hors Docker, mettez à jour son environnement et redémarrez-le.</p></section>
<section class="step"><h3>3. Installer le collecteur sur le serveur source</h3><p><a class="nav-link" id="collector-download">Télécharger le script du collecteur</a></p><p id="collector-help"></p><pre class="code-box" id="collector-config"></pre><button class="secondary" data-copy="collector-config">Copier la configuration du collecteur</button><div id="windows-token" hidden><p>Placez ce jeton seul dans <code>C:\ProgramData\Parralax-DNS\collector.token</code> et limitez l’accès au compte qui exécute le collecteur.</p><pre class="code-box" id="token-value"></pre><button class="secondary" data-copy="token-value">Copier le jeton</button></div><p id="run-help"></p><pre class="code-box" id="collector-command"></pre><button class="secondary" data-copy="collector-command">Copier la commande</button></section>
<section class="step"><h3>4. Vérifier la première collecte</h3><p id="verify-help"></p><p>Une réponse <code>status: success</code> confirme la réception. Fermez cet assistant, puis actualisez la liste. Planifiez ensuite le collecteur avec cron (Plesk) ou le Planificateur de tâches (Windows).</p><button class="secondary" id="refresh-domains">Actualiser les domaines</button><details><summary>La collecte échoue ?</summary><ul><li><strong>401 :</strong> vérifiez que le jeton est identique des deux côtés et, pour Plesk, que l’identifiant de source correspond.</li><li><strong>503 :</strong> vérifiez la variable côté Parralax-DNS et recréez ou redémarrez le service.</li><li><strong>Connexion impossible :</strong> vérifiez l’URL HTTPS, le certificat et l’accès réseau depuis le serveur source.</li></ul></details></section>
</div><p id="copy-status" class="setup-status" role="status"></p></dialog>
</main><script>
const q=s=>document.querySelector(s); const esc=s=>String(s??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
const dateTime=v=>v?new Date(v).toLocaleString('fr-FR',{dateStyle:'short',timeStyle:'medium'}):'Jamais';
const uiWriteHeaders={'X-Parralax-UI-Request':'1'};
let inventory=[];
function comparisonAction(d){const disabled=d.sources.length<2;return '<button '+(disabled?'disabled aria-describedby="compare-hint-'+d.id+'"':'onclick="compareDomain('+d.id+')"')+'>Comparer</button>'+(disabled?'<span class="action-hint" id="compare-hint-'+d.id+'">Deux sources minimum</span>':'')}
async function load(){try{const r=await fetch('/api/domains?include_archived='+q('#archived').checked);if(!r.ok)throw Error('Chargement indisponible');inventory=await r.json();q('#domain-count').textContent='('+inventory.length+')';if(!inventory.length){q('#content').innerHTML='<div class="empty"><h3>'+ (q('#archived').checked?'Aucun domaine pour le moment':'Aucun domaine actif')+'</h3><p>Connectez un serveur Plesk ou Windows DNS avec l’assistant.<br>Si vous avez déjà configuré un fournisseur API, lancez une synchronisation.</p><button onclick="openSetup()">Connecter mon premier serveur</button></div>';return}q('#content').innerHTML='<table><thead><tr><th>Domaine</th><th>Sources</th><th>État</th><th>Dernière collecte</th><th>Actions</th></tr></thead><tbody>'+inventory.map(d=>'<tr><td><strong>'+esc(d.name)+'</strong></td><td>'+d.sources.map(s=>'<div class="source"><strong>'+esc(s.provider)+'</strong> <span class="muted">'+esc(s.remote_status||'—')+'</span>'+(s.provider==='cloudflare'?'<br><a href="/api/sources/'+s.id+'/zone-file">Télécharger BIND</a> · <a href="#" onclick="cloneZone('+s.id+');return false">Cloner vers Infomaniak</a>':'')+'</div>').join('')+'</td><td><span class="badge '+(d.lifecycle_status==='archived'?'archived':'')+'">'+(d.lifecycle_status==='archived'?'Archivé':'Actif')+'</span></td><td class="muted">'+esc(dateTime(d.last_seen_at))+'</td><td class="actions">'+comparisonAction(d)+'<p><a href="/history?domain='+d.id+'">Voir le suivi</a></p></td></tr>').join('')+'</tbody></table>'}catch(e){q('#content').innerHTML='<div class="empty warning">Impossible de charger les domaines. <button onclick="load()">Réessayer</button></div>'}}
function connectivityCard(item){const test=item.last_test;const status=test?test.status:(item.configured?'pending':'pending');const label=test?(test.status==='success'?'Connexion réussie':'Échec du test'):(item.configured?'Pas encore testé':'Non configuré');const details=test?(test.status==='success'?'<pre>'+esc(JSON.stringify(test.response_preview,null,2))+'</pre>':'<p class="warning">'+esc(test.error_message||'Erreur inconnue')+'</p>'):'<p class="muted">'+(item.configured?'Exécutez le test pour vérifier les droits et lire un aperçu de la réponse.':'Ajoutez les variables d’environnement nécessaires puis redémarrez le service.')+'</p>';return '<article class="connector"><header><div><h3>'+esc(item.provider)+'</h3><span class="badge status-'+esc(status)+'">'+esc(label)+'</span></div>'+(item.configured?'<button onclick="rerunConnectivity(\''+esc(item.provider)+'\')">Rejouer</button>':'')+'</header><p class="muted">Dernier test : '+esc(test?dateTime(test.completed_at):'jamais')+(test&&test.latency_ms!==null?' · '+esc(test.latency_ms)+' ms':'')+'</p>'+details+'</article>'}
async function loadSchedule(){const panel=q('#schedule');try{const r=await fetch('/api/sync-schedule');const data=await r.json();if(!r.ok)throw Error(data.detail);if(!data.enabled){panel.innerHTML='<h2>Synchronisation automatique</h2><p class="muted">Désactivée. Définissez <code>SYNC_INTERVAL_MINUTES</code> dans l’environnement puis redémarrez le service.</p>';return}const cadence=data.interval_minutes?'Toutes les '+esc(data.interval_minutes)+' minute(s).':'Au démarrage uniquement.';const next=data.next_run_at?' Prochaine exécution : '+esc(dateTime(data.next_run_at))+'.':'';const last=data.last_completed_at?' Dernier résultat : '+esc(data.last_status||'inconnu')+' · '+esc(dateTime(data.last_completed_at))+'.':' En attente de la première exécution.';panel.innerHTML='<h2>Synchronisation automatique</h2><p><span class="badge '+(data.running?'status-pending':'')+'">'+(data.running?'En cours':'Planifiée')+'</span> '+cadence+next+last+'</p><p class="notice">Les collecteurs Windows DNS et les sources personnalisées sont planifiés depuis leurs serveurs source.</p>'}catch(e){panel.innerHTML='<h2>Synchronisation automatique</h2><p class="warning">Impossible de lire la planification : '+esc(e.message)+'</p>'}}
async function loadConnectivity(){const panel=q('#connectivity');try{const r=await fetch('/api/connectivity-tests');const data=await r.json();if(!r.ok)throw Error(data.detail);panel.innerHTML='<h2>Diagnostic des connecteurs API</h2><p class="notice">Chaque test effectue une lecture non destructive et conserve un aperçu limité de la réponse, sans métadonnées brutes ni secrets.</p><div class="connector-grid">'+data.providers.map(connectivityCard).join('')+'</div><p class="notice">'+esc(data.windows_dns_note)+'</p>'}catch(e){panel.innerHTML='<h2>Diagnostic des connecteurs API</h2><p class="warning">Impossible de charger les diagnostics : '+esc(e.message)+'</p>'}}
async function rerunConnectivity(provider){q('#diagnostic-message').textContent='Test '+provider+' en cours…';try{const r=await fetch('/api/connectivity-tests/'+encodeURIComponent(provider)+'/rerun',{method:'POST',headers:uiWriteHeaders});const data=await r.json();if(!r.ok)throw Error(data.detail);q('#diagnostic-message').textContent=provider+' : '+(data.status==='success'?'connexion réussie.':'échec — consultez le détail.');await loadConnectivity()}catch(e){q('#diagnostic-message').textContent='Erreur de test : '+e.message}}
async function testAllConnectivity(){const b=q('#diagnostics');b.disabled=true;q('#diagnostic-message').textContent='Tests des connecteurs en cours…';try{const r=await fetch('/api/connectivity-tests',{method:'POST',headers:uiWriteHeaders});const data=await r.json();if(!r.ok)throw Error(data.detail);q('#diagnostic-message').textContent=data.results.length?data.results.map(x=>x.provider+': '+x.status).join(' · '):'Aucun connecteur API n’est configuré.';await loadConnectivity()}catch(e){q('#diagnostic-message').textContent='Erreur de test : '+e.message}finally{b.disabled=false}}
const dnsRecord=r=>esc(r.name+'  '+r.type+'  '+r.value+(r.ttl?'  TTL '+r.ttl:''));
async function compareDomain(id){if(!inventory.some(d=>d.id===id&&d.sources.length>=2))return;const panel=q('#comparison');panel.innerHTML='<div class="comparison">Analyse des sources en cours…</div>';try{const r=await fetch('/api/domains/'+id+'/comparison');const d=await r.json();if(!r.ok)throw Error(d.detail);if(d.source_count<2){panel.innerHTML='<div class="comparison"><button class="close" onclick="q(\'#comparison\').innerHTML=\'\'">Fermer</button><h2>Comparaison indisponible</h2><p>Ce domaine n’a qu’une source connue.</p></div>';return}const profiles=d.profiles.map(p=>'<dl class="profile"><strong>'+esc(p.source)+'</strong>'+Object.entries(p).filter(([k])=>!['source','provider'].includes(k)).map(([k,v])=>'<dt>'+esc(k)+'</dt><dd>'+esc(Array.isArray(v)?v.join(', '):v)+'</dd>').join('')+'</dl>').join('');const only=Object.entries(d.dns.only_by_source).filter(([,x])=>x.length).map(([s,x])=>'<h3>Présents seulement chez '+esc(s)+'</h3><ul class="records">'+x.map(v=>'<li>'+dnsRecord(v)+'</li>').join('')+'</ul>').join('')||'<p class="muted">Aucun enregistrement exclusif détecté.</p>';const conflicts=d.dns.conflicts.map(c=>'<li><strong>'+esc(c.name+'  '+c.type)+'</strong> — valeurs ou paramètres divergents</li>').join('')||'<li>Aucun conflit direct détecté.</li>';const errors=Object.entries(d.dns.errors).map(([s,e])=>'<li>'+esc(s)+' : '+esc(e)+'</li>').join('');panel.innerHTML='<div class="comparison"><button class="close" onclick="q(\'#comparison\').innerHTML=\'\'">Fermer</button><h2>Comparaison · '+esc(d.domain)+'</h2><p class="muted">'+d.dns.summary.common+' commun(s) · '+d.dns.summary.different+' présence(s) exclusive(s) · '+d.dns.summary.conflicts+' conflit(s).</p><div class="profiles">'+profiles+'</div><h3>Différences DNS</h3>'+only+'<h3>Conflits sur le même nom et type</h3><ul class="records">'+conflicts+'</ul>'+(errors?'<h3 class="warning">Lectures DNS indisponibles</h3><ul class="records warning">'+errors+'</ul>':'')+'</div>'}catch(e){panel.innerHTML='<div class="comparison warning">Erreur de comparaison : '+esc(e.message)+'</div>'}}
async function cloneZone(sourceId){const target=prompt('Nouvelle zone Infomaniak à créer (elle ne doit pas déjà exister) :');if(!target)return;if(!confirm('Créer la zone '+target+' chez Infomaniak avec l’export BIND de Cloudflare ?'))return;try{const r=await fetch('/api/sources/'+sourceId+'/clone-to-infomaniak',{method:'POST',headers:{...uiWriteHeaders,'Content-Type':'application/json'},body:JSON.stringify({target_zone:target})});const data=await r.json();if(!r.ok)throw Error(data.detail);q('#message').textContent='Zone '+data.target_zone+' créée chez Infomaniak.'}catch(e){q('#message').textContent='Erreur de clonage : '+e.message}}
function openSetup(){q('#tools').open=false;q('#setup-dialog').showModal();if(!q('#collector-url').value&&location.protocol==='https:')q('#collector-url').value=location.origin}
q('#open-diagnostics').onclick=()=>{q('#tools').open=false;q('#diagnostics-dialog').showModal();loadConnectivity()};
document.addEventListener('click',e=>{if(!q('#tools').contains(e.target))q('#tools').open=false});
document.addEventListener('keydown',e=>{if(e.key==='Escape')q('#tools').open=false});
let setupToken='';
function clearSetup(){setupToken='';q('#setup-instructions').hidden=true;for(const id of ['server-config','collector-config','token-value','collector-command','copy-status','setup-status'])q('#'+id).textContent='';q('#generate-token').textContent='Générer le jeton et les instructions';q('#collector-download').removeAttribute('href')}
q('#setup-dialog').addEventListener('close',clearSetup);
q('#collector-kind').onchange=()=>{clearSetup();const windows=q('#collector-kind').value==='windows';q('#source-field').hidden=windows;q('#source-help').hidden=windows;q('#collector-source').disabled=windows};
for(const id of ['collector-source','collector-url'])q('#'+id).addEventListener('input',()=>{q('#collector-url').setCustomValidity('');clearSetup()});
const shellQuote=value=>"'"+value.replace(/'/g,"'\"'\"'")+"'";
q('#setup-form').onsubmit=e=>{
  e.preventDefault();
  let base;
  try{const url=new URL(q('#collector-url').value);if(url.protocol!=='https:'||url.username||url.password||url.search||url.hash)throw Error();base=url.href.replace(/\/$/,'')}
  catch{q('#collector-url').setCustomValidity('Utilisez une URL HTTPS sans identifiants, paramètres ni fragment.');q('#collector-url').reportValidity();return}
  if(!setupToken){const bytes=new Uint8Array(32);crypto.getRandomValues(bytes);setupToken=Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('')}
  const windows=q('#collector-kind').value==='windows';const source=q('#collector-source').value.trim().toLowerCase();
  q('#server-config').textContent=windows?'WINDOWS_DNS_COLLECTOR_TOKEN='+setupToken:"CUSTOM_DNS_COLLECTOR_TOKENS='"+JSON.stringify({[source]:setupToken})+"'";
  q('#server-help').textContent=windows?'Le jeton Windows est partagé par les collecteurs Windows de cette instance. Si vous en avez déjà un, conservez-le ; son remplacement exige de mettre à jour les collecteurs existants.':'Si CUSTOM_DNS_COLLECTOR_TOKENS existe déjà, ajoutez cette entrée dans son objet JSON en conservant les autres sources. Remplacer le jeton d’une source exige de mettre à jour son collecteur.';
  q('#collector-download').href='/collectors/download/'+(windows?'windows':'plesk');
  q('#windows-token').hidden=!windows;
  q('#token-value').textContent=windows?setupToken:'';
  q('#collector-help').textContent=windows?'Avec Windows PowerShell 5.1 et le module DnsServer, placez le script dans C:\\Program Files\\Parralax-DNS. Créez C:\\ProgramData\\Parralax-DNS, puis enregistrez ce JSON dans Sync-ParralaxDns.json à cet emplacement.':'Sur le serveur Plesk Linux, installez bash, jq et curl, puis placez le script dans /opt/parralax-plesk-collector/collect-plesk-dns.sh. Créez /etc/parralax-plesk-collector.env avec ce contenu et limitez ses permissions à 0600.';
  q('#collector-config').textContent=windows?JSON.stringify({apiBaseUrl:base,collectorTokenFile:'C:\\ProgramData\\Parralax-DNS\\collector.token',timeoutSeconds:120,maxAttempts:3,includeReverseLookupZones:false},null,2):'PARRALAX_API_URL='+shellQuote(base+'/api/collectors/custom-dns/sync')+'\nPARRALAX_SOURCE='+source+'\nPARRALAX_SOURCE_TOKEN='+setupToken;
  q('#run-help').textContent=windows?'Lancez cette commande dans une console PowerShell administrateur sur le serveur DNS :':'Depuis le serveur Plesk, avec un compte autorisé à lire toutes les zones, vérifiez d’abord la collecte sans envoi :';
  q('#collector-command').textContent=windows?"& 'C:\\Program Files\\Parralax-DNS\\Sync-ParralaxDns.ps1' -ConfigPath 'C:\\ProgramData\\Parralax-DNS\\Sync-ParralaxDns.json' -Verbose":"chmod 0600 /etc/parralax-plesk-collector.env\nchmod 0750 /opt/parralax-plesk-collector/collect-plesk-dns.sh\nset -a\n. /etc/parralax-plesk-collector.env\nset +a\n/opt/parralax-plesk-collector/collect-plesk-dns.sh --dry-run";
  q('#verify-help').textContent=windows?'La commande précédente envoie les zones du serveur à Parralax-DNS.':'Vérifiez le JSON obtenu, puis relancez /opt/parralax-plesk-collector/collect-plesk-dns.sh sans --dry-run pour envoyer les données.';
  q('#setup-instructions').hidden=false;q('#setup-status').textContent='Instructions prêtes. Le jeton doit encore être activé dans Parralax-DNS.';q('#generate-token').textContent='Afficher les instructions';q('#setup-instructions').scrollIntoView({block:'start',behavior:'smooth'});
};
for(const button of document.querySelectorAll('[data-copy]'))button.onclick=async()=>{const node=q('#'+button.dataset.copy);try{await navigator.clipboard.writeText(node.textContent);q('#copy-status').textContent='Copié dans le presse-papiers.';const label=button.textContent;button.textContent='Copié ✓';setTimeout(()=>button.textContent=label,2000)}catch{const range=document.createRange();range.selectNodeContents(node);const selection=window.getSelection();selection.removeAllRanges();selection.addRange(range);q('#copy-status').textContent='Copie automatique indisponible. Texte sélectionné : utilisez Ctrl+C ou ⌘C.'}};
q('#refresh-domains').onclick=()=>{q('#setup-dialog').close();load()};

q('#sync').onclick=async()=>{const b=q('#sync');b.disabled=true;q('#message').textContent='Synchronisation en cours…';try{const r=await fetch('/api/sync',{method:'POST',headers:uiWriteHeaders});const data=await r.json();if(!r.ok)throw Error(data.detail);q('#message').textContent=data.results.map(x=>x.provider+': '+x.status+(x.discovered!==undefined?' ('+x.discovered+' trouvés)':'')).join(' · ');await load();await loadSchedule()}catch(e){q('#message').textContent='Erreur : '+e.message}finally{b.disabled=false}};q('#diagnostics').onclick=testAllConnectivity;q('#archived').onchange=load;load();loadSchedule();
</script></body></html>'''


DOCUMENTATION_LINK = '<a class="nav-link" href="/api/docs" target="_blank" rel="noopener">Guide API</a>' if API_DOCS_ENABLED else ""


HISTORY_HTML = r'''<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Historique · Parralax-DNS</title>
<style>
:root { color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, sans-serif; color: #182231; background: #f5f7fa; }
body { margin: 0; } main { max-width: 1100px; margin: 48px auto; padding: 0 24px; } h1 { margin: 0; font-size: 2rem; }.sub{color:#637083;margin:8px 0 26px}.toolbar{display:flex;gap:12px;align-items:center;margin-bottom:20px;flex-wrap:wrap}.nav-link{display:inline-block;border:1px solid #cdd8e5;border-radius:8px;padding:9px 14px;background:#fff;color:#135fca;font-weight:650;text-decoration:none}.filter,select{border:1px solid #cdd8e5;border-radius:8px;padding:9px 12px;font:inherit}.filter{min-width:220px}button{border:0;border-radius:8px;padding:8px 12px;background:#135fca;color:#fff;font-weight:650;cursor:pointer}table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e0e6ed;border-radius:12px;overflow:hidden}th,td{padding:13px 14px;border-bottom:1px solid #e9edf2;text-align:left;vertical-align:top}th{color:#556577;font-size:.78rem;text-transform:uppercase;letter-spacing:.04em;background:#fafbfd}tr:last-child td{border-bottom:0}.muted{color:#637083;font-size:.86rem}.badge{display:inline-block;padding:3px 8px;border-radius:99px;background:#edf1f5;color:#526274;font-size:.78rem;font-weight:700}.created,.restored{background:#e7f7eb;color:#196638}.archived{background:#f1eef2;color:#735e75}.updated{background:#e8f1ff;color:#135fca}.zone_cloned{background:#fff3dc;color:#986400}.empty{padding:32px;background:white;border:1px dashed #c8d1dc;border-radius:12px;color:#637083}.error{color:#a33d10}.domain-detail{margin:0 0 24px;padding:20px;background:#fff;border:1px solid #dce5ef;border-radius:12px}.domain-detail h2{margin:0 0 5px;font-size:1.2rem}.metadata-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px;margin-top:14px}.metadata-card{border:1px solid #e1e7ef;border-radius:9px;padding:14px}.metadata-card h3{margin:0 0 4px;font-size:1rem}.metadata-card pre{margin:12px 0 0;padding:12px;max-height:360px;overflow:auto;background:#f6f8fb;border-radius:6px;font-size:.78rem;line-height:1.45;white-space:pre-wrap;word-break:break-word}.metadata-card details{margin-top:12px}.metadata-card summary{cursor:pointer;font-weight:650}.snapshot-controls{margin-top:16px;padding-top:12px;border-top:1px solid #e1e7ef}.snapshot-controls h4,.snapshot-result h5{margin:0 0 8px;font-size:.9rem}.snapshot-controls label{display:block;margin:7px 0;font-size:.84rem}.snapshot-controls select{width:100%;margin-top:3px}.snapshot-result{margin-top:12px}.snapshot-result details{padding:8px 0;border-top:1px solid #edf1f5}.snapshot-result pre{max-height:180px}
</style></head><body><main>
<h1>Historique</h1><p class="sub">Journal append-only des découvertes, mises à jour, archivages, restaurations et clonages. Le suivi d’un domaine affiche aussi ses métadonnées actuelles.</p>
<div class="toolbar"><a class="nav-link" href="/">← Inventaire</a>{{DOCUMENTATION_LINK}}<input id="filter" class="filter" type="search" placeholder="Filtrer par domaine ou source"></div>
<section id="domain-detail" class="domain-detail" hidden aria-live="polite"></section>
<div id="content" aria-live="polite"><div class="empty">Chargement de l’historique…</div></div>
</main><script>
const q=s=>document.querySelector(s);const esc=s=>String(s??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));const fmt=v=>v?new Date(v).toLocaleString('fr-FR',{dateStyle:'medium',timeStyle:'medium'}):'—';let entries=[];const domainParam=new URLSearchParams(location.search).get('domain');
const json=v=>esc(JSON.stringify(v??{},null,2));
const recordsFor=metadata=>metadata?.dns_records??metadata?.records;
function sourceCard(source){const records=recordsFor(source.metadata);const configuration={...source.metadata};delete configuration.dns_records;delete configuration.records;delete configuration.dns_records_error;const recordContent=Array.isArray(records)?'<details open><summary>Enregistrements DNS ('+esc(records.length)+')</summary><pre>'+json(records)+'</pre></details>':(source.metadata?.dns_records_error?'<p class="error">Lecture DNS indisponible : '+esc(source.metadata.dns_records_error)+'</p>':'<p class="muted">Les enregistrements DNS seront disponibles après la prochaine synchronisation.</p>');return '<article class="metadata-card"><h3>'+esc(source.provider)+'</h3><p class="muted">ID externe : '+esc(source.external_id)+' · État : '+esc(source.remote_status||source.lifecycle_status||'—')+'</p><details open><summary>Configuration du FQDN</summary><pre>'+json(configuration)+'</pre></details>'+recordContent+'<section id="snapshots-'+esc(source.id)+'" class="snapshot-controls"><p class="muted">Chargement des synchronisations…</p></section></article>'}
function renderDomainDetail(domain){const panel=q('#domain-detail');const sources=domain.sources||[];panel.hidden=false;panel.innerHTML='<h2>Suivi · '+esc(domain.name)+'</h2><p class="muted">Configuration et métadonnées actuelles reçues lors de la dernière synchronisation, pour chaque source du domaine.</p><div class="metadata-grid">'+(sources.length?sources.map(source=>sourceCard(source)).join(''):'<p class="muted">Aucune source enregistrée.</p>')+'</div>';sources.forEach(source=>loadSourceSnapshots(source,domain.name))}
const snapshotLabel=s=>fmt(s.run_completed_at||s.captured_at)+' · '+esc(s.trigger||'manual');
async function loadSourceSnapshots(source,domainName){const panel=q('#snapshots-'+source.id);try{const r=await fetch('/api/sources/'+source.id+'/snapshots');const data=await r.json();if(!r.ok)throw Error(data.detail||'Erreur inconnue');const snapshots=data.snapshots||[];if(snapshots.length<2){panel.innerHTML='<p class="muted">La comparaison historique sera disponible après deux synchronisations de cette source.</p>';return}const options=snapshots.map(snapshot=>'<option value="'+esc(snapshot.sync_run_id)+'">'+snapshotLabel(snapshot)+'</option>').join('');panel.innerHTML='<h4>Comparer deux synchronisations</h4><label>Avant <select onchange="updateSnapshotButton('+source.id+')" id="before-'+source.id+'">'+options+'</select></label><label>Après <select onchange="updateSnapshotButton('+source.id+')" id="after-'+source.id+'">'+options+'</select></label><button id="compare-snapshots-'+source.id+'" onclick="compareSourceSnapshots('+source.id+',\''+esc(domainName)+'\')">Comparer</button><div id="snapshot-result-'+source.id+'"></div>';q('#before-'+source.id).selectedIndex=1}catch(e){panel.innerHTML='<p class="error">Impossible de charger les synchronisations : '+esc(e.message)+'</p>'}}
function updateSnapshotButton(id){const disabled=q('#before-'+id).value===q('#after-'+id).value;const button=q('#compare-snapshots-'+id);button.disabled=disabled;button.title=disabled?'Choisissez deux synchronisations distinctes':''}
function recordLines(records){return records.length?'<pre>'+json(records)+'</pre>':'<p class="muted">Aucun enregistrement.</p>'}
async function compareSourceSnapshots(sourceId,domainName){const before=q('#before-'+sourceId).value;const after=q('#after-'+sourceId).value;const panel=q('#snapshot-result-'+sourceId);if(before===after){panel.innerHTML='<p class="error">Choisissez deux synchronisations distinctes.</p>';return}panel.innerHTML='<p class="muted">Comparaison en cours…</p>';try{const r=await fetch('/api/sources/'+sourceId+'/snapshots/compare?before_run_id='+encodeURIComponent(before)+'&after_run_id='+encodeURIComponent(after));const data=await r.json();if(!r.ok)throw Error(data.detail||'Erreur inconnue');const comparison=data.comparison;const summary=comparison.summary;const changes=comparison.records.changed.map(change=>'<details><summary>'+esc(change.name)+' · '+esc(change.type)+'</summary><p>Avant</p>'+recordLines(change.before)+'<p>Après</p>'+recordLines(change.after)+'</details>').join('')||'<p class="muted">Aucune modification sur un nom et type existants.</p>';const configuration=comparison.configuration_changes.map(change=>'<details><summary>'+esc(change.field)+'</summary><p>Avant</p><pre>'+json(change.before)+'</pre><p>Après</p><pre>'+json(change.after)+'</pre></details>').join('')||'<p class="muted">Aucune modification de configuration hors DNS.</p>';panel.innerHTML='<div class="snapshot-result"><p><strong>'+esc(summary.added)+' ajouté(s) · '+esc(summary.removed)+' supprimé(s) · '+esc(summary.changed)+' modifié(s)</strong></p><h5>Ajoutés</h5>'+recordLines(comparison.records.added)+'<h5>Supprimés</h5>'+recordLines(comparison.records.removed)+'<h5>Modifiés</h5>'+changes+'<h5>Configuration du FQDN</h5>'+configuration+'</div>'}catch(e){panel.innerHTML='<p class="error">Impossible de comparer les synchronisations : '+esc(e.message)+'</p>'}}
async function loadDomainDetail(){if(!domainParam)return;const panel=q('#domain-detail');panel.hidden=false;panel.innerHTML='<p class="muted">Chargement des métadonnées du domaine…</p>';try{const r=await fetch('/api/domains/'+encodeURIComponent(domainParam));const domain=await r.json();if(!r.ok)throw Error(domain.detail||'Domaine introuvable');renderDomainDetail(domain)}catch(e){panel.innerHTML='<p class="error">Impossible de charger les métadonnées : '+esc(e.message)+'</p>'}}
function render(){const needle=q('#filter').value.trim().toLowerCase();const visible=entries.filter(e=>{if(domainParam&&String(e.domain_id)!==domainParam)return false;return !needle||[e.domain_name,e.source,e.event_type,e.trigger,e.summary].some(v=>String(v??'').toLowerCase().includes(needle))});if(!visible.length){q('#content').innerHTML='<div class="empty">Aucun événement correspondant.</div>';return}q('#content').innerHTML='<table><thead><tr><th>Date</th><th>Domaine</th><th>Source</th><th>Origine</th><th>Événement</th><th>Détail</th></tr></thead><tbody>'+visible.map(e=>'<tr><td class="muted">'+esc(fmt(e.occurred_at))+'</td><td><strong>'+esc(e.domain_name)+'</strong></td><td class="muted">'+esc(e.source||'Domaine unifié')+'</td><td class="muted">'+esc(e.trigger||'action directe')+'</td><td><span class="badge '+esc(e.event_type)+'">'+esc(e.event_type)+'</span></td><td>'+esc(e.summary)+'</td></tr>').join('')+'</tbody></table>'}
async function load(){try{const r=await fetch('/api/history?limit=200');const data=await r.json();if(!r.ok)throw Error(data.detail||'Erreur inconnue');entries=data;render()}catch(e){q('#content').innerHTML='<div class="empty error">Impossible de charger l’historique : '+esc(e.message)+'</div>'}}q('#filter').addEventListener('input',render);loadDomainDetail();load();
</script></body></html>'''
