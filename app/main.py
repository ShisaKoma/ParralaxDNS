from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import threading
import time
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import FastAPI, Header, HTTPException, Query, Response
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import insert

from .comparison import compare, compare_source_snapshots
from .database import Database, history, now
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


@asynccontextmanager
async def lifespan(_: FastAPI):
    DB.initialize()
    interval_minutes, run_on_startup = automatic_sync_configuration()
    SCHEDULE_STATE.update({
        "running": False,
        "last_started_at": None,
        "last_completed_at": None,
        "last_status": None,
        "next_run_at": None,
    })
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


@app.get("/favicon.ico", include_in_schema=False, status_code=204)
def favicon() -> Response:
    return Response(status_code=204)


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
def test_all_connectivity():
    return {"results": [run_connectivity_test(provider) for provider in configured_providers()]}


@app.post("/api/connectivity-tests/{provider_name}/rerun", tags=["Diagnostics"], summary="Rejouer le test d'un connecteur")
def rerun_connectivity_test(provider_name: str):
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
def sync():
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
def clone_to_infomaniak(source_id: int, payload: CloneRequest):
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


HTML = r'''<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Parralax-DNS</title>
<style>
:root { color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, sans-serif; color: #182231; background: #f5f7fa; }
body { margin: 0; } main { max-width: 1100px; margin: 48px auto; padding: 0 24px; }
h1 { margin: 0; font-size: 2rem; } .sub { color: #637083; margin: 8px 0 26px; }
.toolbar { display:flex; gap:12px; align-items:center; margin-bottom:20px; flex-wrap:wrap; } button { border:0; border-radius:8px; padding:10px 16px; background:#135fca; color:white; font-weight:650; cursor:pointer; } button:disabled{opacity:.65;cursor:wait}.nav-link{display:inline-block;border:1px solid #cdd8e5;border-radius:8px;padding:9px 14px;background:#fff;color:#135fca;font-weight:650;text-decoration:none} label{font-size:.9rem} #message{font-size:.9rem;color:#4a5b70}
table { width:100%; border-collapse:collapse; background:#fff; border:1px solid #e0e6ed; border-radius:12px; overflow:hidden; } th,td { padding:13px 14px; border-bottom:1px solid #e9edf2; text-align:left; vertical-align:top; } th { color:#556577; font-size:.78rem; text-transform:uppercase; letter-spacing:.04em; background:#fafbfd; } tr:last-child td{border-bottom:0}.badge{display:inline-block;padding:3px 8px;border-radius:99px;background:#e7f7eb;color:#196638;font-size:.78rem;font-weight:700}.archived{background:#f1eef2;color:#735e75}.source{margin:0 0 5px}.muted{color:#637083;font-size:.86rem}.actions a{color:#135fca;font-size:.86rem}.empty{padding:32px;background:white;border:1px dashed #c8d1dc;border-radius:12px;color:#637083}.comparison{margin-top:24px;padding:20px;background:#fff;border:1px solid #dce5ef;border-radius:12px}.comparison h2{margin:0 0 12px;font-size:1.15rem}.comparison h3{margin:18px 0 7px;font-size:1rem}.profiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:10px}.profile{background:#f7f9fc;border-radius:8px;padding:12px}.profile dt{font-size:.78rem;color:#637083;margin-top:7px}.profile dd{margin:1px 0;word-break:break-word}.warning{color:#9e4b00}.records{margin:6px 0;padding-left:20px;font-family:ui-monospace,SFMono-Regular,monospace;font-size:.82rem}.close{float:right;background:#e8edf3;color:#314154;padding:6px 10px}
.schedule,.connectivity{margin:0 0 24px;padding:20px;background:#fff;border:1px solid #dce5ef;border-radius:12px}.schedule h2,.connectivity h2{font-size:1.1rem;margin:0 0 5px}.schedule p{margin:6px 0}.connector-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:10px;margin-top:14px}.connector{border:1px solid #e1e7ef;border-radius:9px;padding:13px}.connector header{display:flex;justify-content:space-between;align-items:center;gap:8px}.connector h3{margin:0;font-size:1rem}.connector button{padding:6px 9px;font-size:.8rem}.connector pre{margin:10px 0 0;padding:10px;max-height:180px;overflow:auto;background:#f6f8fb;border-radius:6px;font-size:.75rem;white-space:pre-wrap;word-break:break-word}.status-failed{background:#fff1eb;color:#a33d10}.status-pending{background:#edf1f5;color:#526274}.notice{margin:0;color:#637083;font-size:.86rem}
</style></head><body><main>
<h1>Parralax-DNS</h1><p class="sub">Inventaire synchronisé, archivage non destructif et historique des changements.</p>
<div class="toolbar"><button id="sync">Synchroniser maintenant</button><button id="diagnostics">Tester les API</button><a class="nav-link" href="/history">Historique</a>{{DOCUMENTATION_LINK}}<label><input type="checkbox" id="archived"> Afficher les archivés</label><span id="message"></span></div>
<section id="schedule" class="schedule" aria-live="polite"></section>
<section id="connectivity" class="connectivity" aria-live="polite"></section>
<div id="content"></div>
<section id="comparison"></section>
</main><script>
const q=s=>document.querySelector(s); const esc=s=>String(s??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
const dateTime=v=>v?new Date(v).toLocaleString('fr-FR',{dateStyle:'short',timeStyle:'medium'}):'Jamais';
async function load(){const r=await fetch('/api/domains?include_archived='+q('#archived').checked);const data=await r.json(); if(!data.length){q('#content').innerHTML='<div class="empty">Aucun domaine. Configurez les jetons puis lancez une synchronisation.</div>';return} q('#content').innerHTML='<table><thead><tr><th>Domaine</th><th>Sources</th><th>État</th><th>Vu pour la dernière fois</th><th></th></tr></thead><tbody>'+data.map(d=>'<tr><td><strong>'+esc(d.name)+'</strong></td><td>'+d.sources.map(s=>'<div class="source"><strong>'+esc(s.provider)+'</strong> <span class="muted">'+esc(s.remote_status||'—')+'</span>'+(s.provider==='cloudflare'?'<br><a href="/api/sources/'+s.id+'/zone-file">Télécharger BIND</a> · <a href="#" onclick="cloneZone('+s.id+');return false">Cloner vers Infomaniak</a>':'')+'</div>').join('')+'</td><td><span class="badge '+(d.lifecycle_status==='archived'?'archived':'')+'">'+esc(d.lifecycle_status)+'</span></td><td class="muted">'+esc(d.last_seen_at||'—')+'</td><td class="actions"><a href="#" onclick="compareDomain('+d.id+');return false">Comparer</a> · <a href="/history?domain='+d.id+'">Suivi</a></td></tr>').join('')+'</tbody></table>'}
function connectivityCard(item){const test=item.last_test;const status=test?test.status:(item.configured?'pending':'pending');const label=test?(test.status==='success'?'Connexion réussie':'Échec du test'):(item.configured?'Pas encore testé':'Non configuré');const details=test?(test.status==='success'?'<pre>'+esc(JSON.stringify(test.response_preview,null,2))+'</pre>':'<p class="warning">'+esc(test.error_message||'Erreur inconnue')+'</p>'):'<p class="muted">'+(item.configured?'Exécutez le test pour vérifier les droits et lire un aperçu de la réponse.':'Ajoutez les variables d’environnement nécessaires puis redémarrez le service.')+'</p>';return '<article class="connector"><header><div><h3>'+esc(item.provider)+'</h3><span class="badge status-'+esc(status)+'">'+esc(label)+'</span></div>'+(item.configured?'<button onclick="rerunConnectivity(\''+esc(item.provider)+'\')">Rejouer</button>':'')+'</header><p class="muted">Dernier test : '+esc(test?dateTime(test.completed_at):'jamais')+(test&&test.latency_ms!==null?' · '+esc(test.latency_ms)+' ms':'')+'</p>'+details+'</article>'}
async function loadSchedule(){const panel=q('#schedule');try{const r=await fetch('/api/sync-schedule');const data=await r.json();if(!r.ok)throw Error(data.detail);if(!data.enabled){panel.innerHTML='<h2>Synchronisation automatique</h2><p class="muted">Désactivée. Définissez <code>SYNC_INTERVAL_MINUTES</code> dans l’environnement puis redémarrez le service.</p>';return}const cadence=data.interval_minutes?'Toutes les '+esc(data.interval_minutes)+' minute(s).':'Au démarrage uniquement.';const next=data.next_run_at?' Prochaine exécution : '+esc(dateTime(data.next_run_at))+'.':'';const last=data.last_completed_at?' Dernier résultat : '+esc(data.last_status||'inconnu')+' · '+esc(dateTime(data.last_completed_at))+'.':' En attente de la première exécution.';panel.innerHTML='<h2>Synchronisation automatique</h2><p><span class="badge '+(data.running?'status-pending':'')+'">'+(data.running?'En cours':'Planifiée')+'</span> '+cadence+next+last+'</p><p class="notice">Les collecteurs Windows DNS et les sources personnalisées sont planifiés depuis leurs serveurs source.</p>'}catch(e){panel.innerHTML='<h2>Synchronisation automatique</h2><p class="warning">Impossible de lire la planification : '+esc(e.message)+'</p>'}}
async function loadConnectivity(){const panel=q('#connectivity');try{const r=await fetch('/api/connectivity-tests');const data=await r.json();if(!r.ok)throw Error(data.detail);panel.innerHTML='<h2>Diagnostic des connecteurs API</h2><p class="notice">Chaque test effectue une lecture non destructive et conserve un aperçu limité de la réponse, sans métadonnées brutes ni secrets.</p><div class="connector-grid">'+data.providers.map(connectivityCard).join('')+'</div><p class="notice">'+esc(data.windows_dns_note)+'</p>'}catch(e){panel.innerHTML='<h2>Diagnostic des connecteurs API</h2><p class="warning">Impossible de charger les diagnostics : '+esc(e.message)+'</p>'}}
async function rerunConnectivity(provider){q('#message').textContent='Test '+provider+' en cours…';try{const r=await fetch('/api/connectivity-tests/'+encodeURIComponent(provider)+'/rerun',{method:'POST'});const data=await r.json();if(!r.ok)throw Error(data.detail);q('#message').textContent=provider+' : '+(data.status==='success'?'connexion réussie.':'échec — consultez le détail.');await loadConnectivity()}catch(e){q('#message').textContent='Erreur de test : '+e.message}}
async function testAllConnectivity(){const b=q('#diagnostics');b.disabled=true;q('#message').textContent='Tests des connecteurs en cours…';try{const r=await fetch('/api/connectivity-tests',{method:'POST'});const data=await r.json();if(!r.ok)throw Error(data.detail);q('#message').textContent=data.results.length?data.results.map(x=>x.provider+': '+x.status).join(' · '):'Aucun connecteur API n’est configuré.';await loadConnectivity()}catch(e){q('#message').textContent='Erreur de test : '+e.message}finally{b.disabled=false}}
const dnsRecord=r=>esc(r.name+'  '+r.type+'  '+r.value+(r.ttl?'  TTL '+r.ttl:''));
async function compareDomain(id){const panel=q('#comparison');panel.innerHTML='<div class="comparison">Analyse des sources en cours…</div>';try{const r=await fetch('/api/domains/'+id+'/comparison');const d=await r.json();if(!r.ok)throw Error(d.detail);if(d.source_count<2){panel.innerHTML='<div class="comparison"><button class="close" onclick="q(\'#comparison\').innerHTML=\'\'">Fermer</button><h2>Comparaison indisponible</h2><p>Ce domaine n’a qu’une source connue.</p></div>';return}const profiles=d.profiles.map(p=>'<dl class="profile"><strong>'+esc(p.source)+'</strong>'+Object.entries(p).filter(([k])=>!['source','provider'].includes(k)).map(([k,v])=>'<dt>'+esc(k)+'</dt><dd>'+esc(Array.isArray(v)?v.join(', '):v)+'</dd>').join('')+'</dl>').join('');const only=Object.entries(d.dns.only_by_source).filter(([,x])=>x.length).map(([s,x])=>'<h3>Présents seulement chez '+esc(s)+'</h3><ul class="records">'+x.map(v=>'<li>'+dnsRecord(v)+'</li>').join('')+'</ul>').join('')||'<p class="muted">Aucun enregistrement exclusif détecté.</p>';const conflicts=d.dns.conflicts.map(c=>'<li><strong>'+esc(c.name+'  '+c.type)+'</strong> — valeurs ou paramètres divergents</li>').join('')||'<li>Aucun conflit direct détecté.</li>';const errors=Object.entries(d.dns.errors).map(([s,e])=>'<li>'+esc(s)+' : '+esc(e)+'</li>').join('');panel.innerHTML='<div class="comparison"><button class="close" onclick="q(\'#comparison\').innerHTML=\'\'">Fermer</button><h2>Comparaison · '+esc(d.domain)+'</h2><p class="muted">'+d.dns.summary.common+' commun(s) · '+d.dns.summary.different+' présence(s) exclusive(s) · '+d.dns.summary.conflicts+' conflit(s).</p><div class="profiles">'+profiles+'</div><h3>Différences DNS</h3>'+only+'<h3>Conflits sur le même nom et type</h3><ul class="records">'+conflicts+'</ul>'+(errors?'<h3 class="warning">Lectures DNS indisponibles</h3><ul class="records warning">'+errors+'</ul>':'')+'</div>'}catch(e){panel.innerHTML='<div class="comparison warning">Erreur de comparaison : '+esc(e.message)+'</div>'}}
async function cloneZone(sourceId){const target=prompt('Nouvelle zone Infomaniak à créer (elle ne doit pas déjà exister) :');if(!target)return;if(!confirm('Créer la zone '+target+' chez Infomaniak avec l’export BIND de Cloudflare ?'))return;try{const r=await fetch('/api/sources/'+sourceId+'/clone-to-infomaniak',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target_zone:target})});const data=await r.json();if(!r.ok)throw Error(data.detail);q('#message').textContent='Zone '+data.target_zone+' créée chez Infomaniak.'}catch(e){q('#message').textContent='Erreur de clonage : '+e.message}}
q('#sync').onclick=async()=>{const b=q('#sync');b.disabled=true;q('#message').textContent='Synchronisation en cours…';try{const r=await fetch('/api/sync',{method:'POST'});const data=await r.json();if(!r.ok)throw Error(data.detail);q('#message').textContent=data.results.map(x=>x.provider+': '+x.status+(x.discovered!==undefined?' ('+x.discovered+' trouvés)':'')).join(' · ');await load();await loadSchedule()}catch(e){q('#message').textContent='Erreur : '+e.message}finally{b.disabled=false}};q('#diagnostics').onclick=testAllConnectivity;q('#archived').onchange=load;load();loadSchedule();loadConnectivity();
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
async function loadSourceSnapshots(source,domainName){const panel=q('#snapshots-'+source.id);try{const r=await fetch('/api/sources/'+source.id+'/snapshots');const data=await r.json();if(!r.ok)throw Error(data.detail||'Erreur inconnue');const snapshots=data.snapshots||[];if(snapshots.length<2){panel.innerHTML='<p class="muted">La comparaison historique sera disponible après deux synchronisations de cette source.</p>';return}const options=snapshots.map(snapshot=>'<option value="'+esc(snapshot.sync_run_id)+'">'+snapshotLabel(snapshot)+'</option>').join('');panel.innerHTML='<h4>Comparer deux synchronisations</h4><label>Avant <select id="before-'+source.id+'">'+options+'</select></label><label>Après <select id="after-'+source.id+'">'+options+'</select></label><button onclick="compareSourceSnapshots('+source.id+',\''+esc(domainName)+'\')">Comparer</button><div id="snapshot-result-'+source.id+'"></div>';q('#before-'+source.id).selectedIndex=1}catch(e){panel.innerHTML='<p class="error">Impossible de charger les synchronisations : '+esc(e.message)+'</p>'}}
function recordLines(records){return records.length?'<pre>'+json(records)+'</pre>':'<p class="muted">Aucun enregistrement.</p>'}
async function compareSourceSnapshots(sourceId,domainName){const before=q('#before-'+sourceId).value;const after=q('#after-'+sourceId).value;const panel=q('#snapshot-result-'+sourceId);if(before===after){panel.innerHTML='<p class="error">Choisissez deux synchronisations distinctes.</p>';return}panel.innerHTML='<p class="muted">Comparaison en cours…</p>';try{const r=await fetch('/api/sources/'+sourceId+'/snapshots/compare?before_run_id='+encodeURIComponent(before)+'&after_run_id='+encodeURIComponent(after));const data=await r.json();if(!r.ok)throw Error(data.detail||'Erreur inconnue');const comparison=data.comparison;const summary=comparison.summary;const changes=comparison.records.changed.map(change=>'<details><summary>'+esc(change.name)+' · '+esc(change.type)+'</summary><p>Avant</p>'+recordLines(change.before)+'<p>Après</p>'+recordLines(change.after)+'</details>').join('')||'<p class="muted">Aucune modification sur un nom et type existants.</p>';const configuration=comparison.configuration_changes.map(change=>'<details><summary>'+esc(change.field)+'</summary><p>Avant</p><pre>'+json(change.before)+'</pre><p>Après</p><pre>'+json(change.after)+'</pre></details>').join('')||'<p class="muted">Aucune modification de configuration hors DNS.</p>';panel.innerHTML='<div class="snapshot-result"><p><strong>'+esc(summary.added)+' ajouté(s) · '+esc(summary.removed)+' supprimé(s) · '+esc(summary.changed)+' modifié(s)</strong></p><h5>Ajoutés</h5>'+recordLines(comparison.records.added)+'<h5>Supprimés</h5>'+recordLines(comparison.records.removed)+'<h5>Modifiés</h5>'+changes+'<h5>Configuration du FQDN</h5>'+configuration+'</div>'}catch(e){panel.innerHTML='<p class="error">Impossible de comparer les synchronisations : '+esc(e.message)+'</p>'}}
async function loadDomainDetail(){if(!domainParam)return;const panel=q('#domain-detail');panel.hidden=false;panel.innerHTML='<p class="muted">Chargement des métadonnées du domaine…</p>';try{const r=await fetch('/api/domains/'+encodeURIComponent(domainParam));const domain=await r.json();if(!r.ok)throw Error(domain.detail||'Domaine introuvable');renderDomainDetail(domain)}catch(e){panel.innerHTML='<p class="error">Impossible de charger les métadonnées : '+esc(e.message)+'</p>'}}
function render(){const needle=q('#filter').value.trim().toLowerCase();const visible=entries.filter(e=>{if(domainParam&&String(e.domain_id)!==domainParam)return false;return !needle||[e.domain_name,e.source,e.event_type,e.trigger,e.summary].some(v=>String(v??'').toLowerCase().includes(needle))});if(!visible.length){q('#content').innerHTML='<div class="empty">Aucun événement correspondant.</div>';return}q('#content').innerHTML='<table><thead><tr><th>Date</th><th>Domaine</th><th>Source</th><th>Origine</th><th>Événement</th><th>Détail</th></tr></thead><tbody>'+visible.map(e=>'<tr><td class="muted">'+esc(fmt(e.occurred_at))+'</td><td><strong>'+esc(e.domain_name)+'</strong></td><td class="muted">'+esc(e.source||'Domaine unifié')+'</td><td class="muted">'+esc(e.trigger||'action directe')+'</td><td><span class="badge '+esc(e.event_type)+'">'+esc(e.event_type)+'</span></td><td>'+esc(e.summary)+'</td></tr>').join('')+'</tbody></table>'}
async function load(){try{const r=await fetch('/api/history?limit=200');const data=await r.json();if(!r.ok)throw Error(data.detail||'Erreur inconnue');entries=data;render()}catch(e){q('#content').innerHTML='<div class="empty error">Impossible de charger l’historique : '+esc(e.message)+'</div>'}}q('#filter').addEventListener('input',render);loadDomainDetail();load();
</script></body></html>'''
