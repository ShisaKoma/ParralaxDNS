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
from typing import Annotated, Any, Literal
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape
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
    NginxOneAppProtectProvider,
    OvhProvider,
    ProviderError,
    TechnitiumDnsProvider,
    WindowsDnsProvider,
)
from .sync import Synchronizer


DB = Database(os.getenv("DATABASE_URL") or os.getenv("DATABASE_PATH", "data/domain_inventory.sqlite3"))
API_PROVIDERS = ("cloudflare", "infomaniak", "ovh", "technitium", "nginx_nim", "nginx_one")
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
    "/api/collectors/network-diagnostics",
}
UI_CONTENT_SECURITY_POLICY = (
    "default-src 'self'; base-uri 'none'; connect-src 'self'; form-action 'self'; "
    "frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; "
    "script-src 'self'; style-src 'self'"
)
APP_ROOT = Path(__file__).resolve().parent
TEMPLATES = Environment(
    loader=FileSystemLoader(APP_ROOT / "templates"),
    autoescape=select_autoescape(("html", "xml")),
)


def render_template(name: str, **context: Any) -> str:
    """Render a browser page with the shared application layout."""
    return TEMPLATES.get_template(name).render(
        api_docs_enabled=API_DOCS_ENABLED,
        **context,
    )


def ui_authentication_configuration() -> tuple[bytes, bytes]:
    """Return the mandatory Basic credentials for the UI and REST API.

    Refuse to start without a complete configuration: otherwise a deployment
    typo could expose the inventory without requiring a login.
    """
    email = os.getenv("PARRALAX_UI_AUTH_EMAIL", "").strip()
    password = os.getenv("PARRALAX_UI_AUTH_PASSWORD", "")
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
    # Fail closed before serving data if UI authentication is not configured.
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
    DB.close()


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
        {"name": "Anomalies", "description": "Rapports réseau historisés envoyés par des agents Linux dédiés."},
        {"name": "Collecteurs", "description": "Inventaires poussés depuis Windows DNS, Plesk, Kubernetes, cPanel ou une source interne."},
        {"name": "Zones", "description": "Export BIND Cloudflare et clonage explicite vers Infomaniak."},
    ],
    docs_url="/api/docs" if API_DOCS_ENABLED else None,
    redoc_url=None,
    openapi_url="/api/openapi.json" if API_DOCS_ENABLED else None,
    lifespan=lifespan,
)


@app.middleware("http")
async def protect_inventory_responses(request: Request, call_next):
    """Protect the browser UI and API with the mandatory Basic credentials."""
    path = request.url.path
    credentials = ui_authentication_configuration()
    has_dedicated_credential = (
        path in UI_AUTH_EXEMPT_PATHS
        or (request.method == "POST" and path in COLLECTOR_SYNC_PATHS)
    )
    if not has_dedicated_credential:
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
    if path in {"/", "/domains", "/history", "/anomalies"} or path.startswith("/domains/"):
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
    if nginx_one_url := os.getenv("NGINX_ONE_URL"):
        if nginx_one_token := os.getenv("NGINX_ONE_API_TOKEN"):
            providers.append(NginxOneAppProtectProvider(
                base_url=nginx_one_url.rstrip("/"),
                namespace=os.getenv("NGINX_ONE_NAMESPACE", "default"),
                api_token=nginx_one_token,
                auth_scheme=os.getenv("NGINX_ONE_AUTH_SCHEME", "APIToken"),
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
    source: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", description="Identifiant configuré de la source, par exemple `shell-001`.")
    zones: list[CustomDnsZone] = Field(max_length=10_000)
    model_config = ConfigDict(json_schema_extra={"example": {
        "source": "shell-001",
        "zones": [{
            "name": "example.org",
            "external_id": "zone-42",
            "remote_status": "active",
            "records": [
                {"name": "@", "type": "MX", "value": "mail.example.org", "priority": 10, "ttl": 3600},
                {"name": "www", "type": "A", "value": "192.0.2.42", "ttl": 300},
            ],
        }],
    }})


class NetworkDiagnosticCheck(BaseModel):
    """One bounded command result. The API never executes the command itself."""

    domain: str | None = Field(default=None, max_length=253, pattern=r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$")
    check_type: Literal["dig", "traceroute", "netstat"]
    status: Literal["ok", "anomaly", "error", "unavailable"]
    exit_code: int | None = Field(default=None, ge=0, le=255)
    duration_ms: int | None = Field(default=None, ge=0, le=3_600_000)
    anomaly_code: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{0,63}$")
    output: str = Field(default="", max_length=16_384)


class NetworkDiagnosticReport(BaseModel):
    agent: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    collected_at: datetime
    complete: bool
    # 360 domaines × (dig + traceroute), plus le contrôle netstat global.
    checks: list[NetworkDiagnosticCheck] = Field(min_length=1, max_length=750)


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


def configured_network_diagnostic_tokens() -> dict[str, str]:
    """Load one diagnostic token per agent without persisting any secret."""
    raw_tokens = os.getenv("NETWORK_DIAGNOSTIC_AGENT_TOKENS", "")
    if not raw_tokens:
        return {}
    try:
        configured = json.loads(raw_tokens)
    except json.JSONDecodeError as exc:
        raise HTTPException(503, "NETWORK_DIAGNOSTIC_AGENT_TOKENS doit contenir un objet JSON valide.") from exc
    if not isinstance(configured, dict):
        raise HTTPException(503, "NETWORK_DIAGNOSTIC_AGENT_TOKENS doit associer un agent à un jeton.")
    tokens = {
        str(agent).strip().lower(): token
        for agent, token in configured.items()
        if isinstance(agent, str) and isinstance(token, str) and token
    }
    if not tokens:
        raise HTTPException(503, "Aucun jeton d'agent de diagnostic valide n'est configuré.")
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
    return render_template(
        "home.html",
        page_title="Parralax-DNS",
        active_navigation="home",
    )


@app.get("/domains", response_class=HTMLResponse, include_in_schema=False)
def inventory_page() -> str:
    return render_template(
        "domains/list.html",
        page_title="Domaines · Parralax-DNS",
        active_navigation="domains",
    )


@app.get("/domains/{domain_id}", response_class=HTMLResponse, include_in_schema=False)
def domain_detail_page(domain_id: int) -> str:
    return render_template(
        "domains/detail.html",
        page_title="Détail du domaine · Parralax-DNS",
        active_navigation="domains",
        domain_id=domain_id,
    )


@app.get("/history", response_class=HTMLResponse, include_in_schema=False)
def history_page() -> str:
    return render_template(
        "history/list.html",
        page_title="Historique · Parralax-DNS",
        active_navigation="history",
    )


@app.get("/anomalies", response_class=HTMLResponse, include_in_schema=False)
def anomalies_page() -> str:
    return render_template(
        "anomalies/list.html",
        page_title="Anomalies réseau · Parralax-DNS",
        active_navigation="anomalies",
    )


@app.get("/domains/{domain_id}/comparison", response_class=HTMLResponse, include_in_schema=False)
def comparison_page(domain_id: int) -> str:
    return render_template(
        "domains/comparison.html",
        page_title="Comparateur DNS · Parralax-DNS",
        active_navigation="domains",
        domain_id=domain_id,
    )


COLLECTOR_DOWNLOADS = {
    "plesk": "collectors/plesk-collector/collect-plesk-dns.sh",
    "kubernetes": "collectors/kubernetes/collect-kubernetes-dns.sh",
    "windows": "collectors/windows-dns/Sync-ParralaxDns.ps1",
    "network-diagnostics": "collectors/network-diagnostics/collect-network-diagnostics.sh",
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


@app.post("/api/domains/{domain_id}/archive", tags=["Inventaire"], summary="Archiver localement un domaine et ses sources")
def archive_domain(domain_id: int):
    item = DB.archive_domain(domain_id)
    if not item:
        raise HTTPException(404, "Domaine introuvable")
    return {"status": "success", "domain": item}


@app.get("/api/domains/{domain_id}/comparison", tags=["Inventaire"], summary="Comparer les sources et les records DNS d'un domaine")
def compare_domain(
    domain_id: int,
    source_ids: Annotated[list[int] | None, Query(description="Au moins deux identifiants de sources du domaine à comparer.")] = None,
):
    item = DB.get_domain(domain_id)
    if not item:
        raise HTTPException(404, "Domaine introuvable")
    if source_ids is not None:
        if len(source_ids) < 2 or len(set(source_ids)) != len(source_ids):
            raise HTTPException(422, "Sélectionnez au moins deux sources distinctes à comparer.")
        selected_sources = [source for source in item["sources"] if source["id"] in set(source_ids)]
        if len(selected_sources) != len(source_ids):
            raise HTTPException(400, "Les sources sélectionnées ne correspondent pas à ce domaine.")
        item = {**item, "sources": selected_sources}
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
        "Pour un collecteur ou une intégration interne. Configurez un jeton distinct "
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


@app.post(
    "/api/collectors/network-diagnostics",
    tags=["Collecteurs", "Anomalies"],
    summary="Recevoir les contrôles réseau d'un agent Linux",
    description=(
        "Enregistre un rapport append-only de commandes autorisées exécutées par l'agent. "
        "Ce flux ne modifie pas l'inventaire DNS et ne déclenche aucun archivage."
    ),
)
def collect_network_diagnostics(
    payload: NetworkDiagnosticReport,
    agent_token: Annotated[str | None, Header(alias="X-Parralax-Agent-Token")] = None,
):
    agent = payload.agent.strip().lower()
    expected_token = configured_network_diagnostic_tokens().get(agent)
    if not agent_token or not expected_token or not secrets.compare_digest(agent_token, expected_token):
        raise HTTPException(401, "Agent de diagnostic ou jeton invalide.")
    if payload.collected_at.tzinfo is None or payload.collected_at.utcoffset() is None:
        raise HTTPException(422, "collected_at doit inclure un fuseau horaire.")
    checks = []
    for check in payload.checks:
        if check.check_type == "netstat" and check.domain is not None:
            raise HTTPException(422, "Le contrôle netstat est global et ne doit pas déclarer de domaine.")
        if check.check_type != "netstat" and check.domain is None:
            raise HTTPException(422, "Les contrôles dig et traceroute doivent déclarer un domaine.")
        if check.status == "ok" and check.anomaly_code is not None:
            raise HTTPException(422, "Un contrôle sans anomalie ne doit pas déclarer anomaly_code.")
        if check.status != "ok" and check.anomaly_code is None:
            raise HTTPException(422, "Un contrôle non conforme doit déclarer anomaly_code.")
        checks.append(check.model_dump())
    report = DB.store_network_diagnostic_report(
        agent=agent,
        collected_at=payload.collected_at.isoformat(timespec="seconds"),
        complete=payload.complete,
        checks=checks,
    )
    return {
        "status": "accepted",
        "run_id": report["id"],
        "collection_status": report["status"],
        "check_count": report["check_count"],
        "anomaly_count": report["anomaly_count"],
    }


@app.get("/api/network-diagnostics", tags=["Anomalies"], summary="Lister les rapports de diagnostic réseau")
def network_diagnostic_reports(limit: Annotated[int, Query(ge=1, le=200)] = 50):
    return DB.list_network_diagnostic_runs(limit)


@app.get("/api/network-diagnostics/{run_id}", tags=["Anomalies"], summary="Lire un rapport de diagnostic réseau")
def network_diagnostic_report(run_id: int):
    report = DB.network_diagnostic_run(run_id)
    if report is None:
        raise HTTPException(404, "Rapport de diagnostic introuvable.")
    return report


@app.get("/api/anomalies/network", tags=["Anomalies"], summary="Lister les anomalies réseau observées")
def network_anomalies(
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    current_only: bool = True,
):
    return DB.list_network_anomalies(limit, current_only=current_only)


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
app.mount("/static", StaticFiles(directory=APP_ROOT / "static"), name="static")
MCP_SERVER = create_mcp_server(lambda: DB, configured_providers)
app.mount("/", protected_mcp_application(MCP_SERVER))
