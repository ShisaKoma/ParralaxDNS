from __future__ import annotations

import json
import hashlib
import base64
import ssl
import time
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from .models import RemoteDomain


class ProviderError(RuntimeError):
    pass


class Provider(Protocol):
    name: str

    def list_domains(self) -> list[RemoteDomain]: ...


def _request_json(url: str, token: str) -> dict[str, Any]:
    request = Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    try:
        with urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise ProviderError(f"HTTP {exc.code} sur {url}: {detail}") from exc
    except (URLError, TimeoutError) as exc:
        raise ProviderError(f"Connexion impossible à {url}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ProviderError(f"Réponse JSON invalide depuis {url}") from exc


@dataclass
class CloudflareProvider:
    token: str
    name: str = "cloudflare"
    base_url: str = "https://api.cloudflare.com/client/v4"

    def list_domains(self) -> list[RemoteDomain]:
        page, items = 1, []
        while True:
            data = _request_json(f"{self.base_url}/zones?{urlencode({'page': page, 'per_page': 50})}", self.token)
            if not data.get("success"):
                raise ProviderError(f"Cloudflare a refusé la liste des zones: {data.get('errors', [])}")
            for zone in data.get("result", []):
                items.append(RemoteDomain(
                    provider=self.name,
                    external_id=str(zone["id"]),
                    name=zone["name"],
                    remote_status=zone.get("status"),
                    metadata=zone,
                ))
            info = data.get("result_info") or {}
            if page >= int(info.get("total_pages", 1)):
                return items
            page += 1

    def export_zone_file(self, zone_id: str) -> str:
        request = Request(
            f"{self.base_url}/zones/{zone_id}/dns_records/export",
            headers={"Authorization": f"Bearer {self.token}", "Accept": "text/plain"},
        )
        try:
            with urlopen(request, timeout=30) as response:
                return response.read().decode("utf-8")
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise ProviderError(f"Export BIND Cloudflare impossible (HTTP {exc.code}): {detail}") from exc
        except (URLError, TimeoutError) as exc:
            raise ProviderError(f"Export BIND Cloudflare impossible: {exc}") from exc

    def list_dns_records(self, zone_id: str) -> list[dict[str, Any]]:
        page, records = 1, []
        while True:
            data = _request_json(
                f"{self.base_url}/zones/{zone_id}/dns_records?{urlencode({'page': page, 'per_page': 100})}",
                self.token,
            )
            if not data.get("success"):
                raise ProviderError(f"Cloudflare a refusé la lecture DNS: {data.get('errors', [])}")
            records.extend(data.get("result", []))
            info = data.get("result_info") or {}
            if page >= int(info.get("total_pages", 1)):
                return records
            page += 1


@dataclass
class InfomaniakProvider:
    token: str
    account_id: str | None = None
    name: str = "infomaniak"
    base_url: str = "https://api.infomaniak.com"

    def list_domains(self) -> list[RemoteDomain]:
        page, items = 1, []
        while True:
            query: dict[str, str | int] = {"page": page}
            if self.account_id:
                query["account_id"] = self.account_id
            data = _request_json(f"{self.base_url}/2/domains/domains?{urlencode(query)}", self.token)
            if data.get("result") != "success":
                raise ProviderError(f"Infomaniak a refusé la liste des domaines: {data}")
            for domain in data.get("data", []):
                items.append(RemoteDomain(
                    provider=self.name,
                    external_id=str(domain["id"]),
                    name=domain["name"],
                    remote_status=domain.get("status") or domain.get("resale_status"),
                    metadata=domain,
                ))
            if page >= int(data.get("pages", 1)):
                return items
            page += 1

    def create_zone_from_raw(self, target_zone: str, raw_zone: str) -> dict[str, Any]:
        body = json.dumps({"skel": raw_zone}).encode("utf-8")
        request = Request(
            f"{self.base_url}/2/zones/{target_zone}",
            data=body,
            method="POST",
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with urlopen(request, timeout=45) as response:
                data = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise ProviderError(f"Création de zone Infomaniak impossible (HTTP {exc.code}): {detail}") from exc
        if data.get("result") != "success":
            raise ProviderError(f"Création de zone Infomaniak refusée: {data}")
        return data.get("data", {})

    def list_dns_records(self, zone: str) -> list[dict[str, Any]]:
        data = _request_json(f"{self.base_url}/2/zones/{zone}?{urlencode({'with': 'records'})}", self.token)
        if data.get("result") != "success":
            raise ProviderError(f"Infomaniak a refusé la lecture DNS: {data}")
        return (data.get("data") or {}).get("records", [])


@dataclass
class WindowsDnsProvider:
    """A complete inventory posted by one Windows DNS Server collector."""

    server: str
    zones: list[dict[str, Any]]

    @property
    def name(self) -> str:
        return f"windows_dns:{self.server.rstrip('.').lower()}"

    def list_domains(self) -> list[RemoteDomain]:
        return [
            RemoteDomain(
                provider=self.name,
                external_id=zone["name"].rstrip(".").lower(),
                name=zone["name"],
                remote_status=zone.get("zone_type") or "unknown",
                metadata={"server": self.server, **zone},
            )
            for zone in self.zones
        ]


@dataclass
class CustomDnsProvider:
    """An inventory pushed by a named DNS source such as Plesk or cPanel."""

    source: str
    zones: list[dict[str, Any]]

    @property
    def name(self) -> str:
        return f"custom:{self.source.strip().lower()}"

    def list_domains(self) -> list[RemoteDomain]:
        return [
            RemoteDomain(
                provider=self.name,
                external_id=str(zone.get("external_id") or zone["name"].rstrip(".").lower()),
                name=zone["name"],
                remote_status=zone.get("remote_status") or "reported",
                metadata={"source": self.source, **zone},
            )
            for zone in self.zones
        ]


@dataclass
class OvhProvider:
    """OVHcloud v1 API client using the documented signed-request scheme."""

    application_key: str
    application_secret: str
    consumer_key: str
    base_url: str = "https://eu.api.ovh.com/1.0"
    name: str = "ovh"
    _time_delta: float | None = None

    def _timestamp(self) -> int:
        if self._time_delta is None:
            request = Request(f"{self.base_url}/auth/time", headers={"X-Ovh-Application": self.application_key})
            try:
                with urlopen(request, timeout=30) as response:
                    server_time = int(json.loads(response.read().decode("utf-8")))
            except (HTTPError, URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
                raise ProviderError(f"Impossible de synchroniser l'horloge avec l'API OVH: {exc}") from exc
            self._time_delta = server_time - time.time()
        return int(time.time() + self._time_delta)

    def _get(self, path: str) -> Any:
        url = f"{self.base_url}{path}"
        timestamp = self._timestamp()
        signature_payload = "+".join((self.application_secret, self.consumer_key, "GET", url, "", str(timestamp)))
        signature = "$1$" + hashlib.sha1(signature_payload.encode("utf-8")).hexdigest()
        request = Request(url, headers={
            "X-Ovh-Application": self.application_key,
            "X-Ovh-Consumer": self.consumer_key,
            "X-Ovh-Timestamp": str(timestamp),
            "X-Ovh-Signature": signature,
            "Accept": "application/json",
        })
        try:
            with urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise ProviderError(f"OVH a refusé {path} (HTTP {exc.code}): {detail}") from exc
        except (URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise ProviderError(f"Lecture OVH impossible pour {path}: {exc}") from exc

    def list_domains(self) -> list[RemoteDomain]:
        domains: list[RemoteDomain] = []
        for service_name in self._get("/domain"):
            encoded = quote(service_name, safe=".")
            domain = self._get(f"/domain/{encoded}")
            service_info = self._get(f"/domain/{encoded}/serviceInfos")
            domains.append(RemoteDomain(
                provider=self.name,
                external_id=service_name,
                name=domain.get("domain") or service_name,
                remote_status=service_info.get("status") or domain.get("transferLockStatus"),
                metadata={**domain, "service_info": service_info},
            ))
        return domains

    def list_dns_records(self, zone_name: str) -> list[dict[str, Any]]:
        encoded = quote(zone_name, safe=".")
        record_ids = self._get(f"/domain/zone/{encoded}/record")
        return [self._get(f"/domain/zone/{encoded}/record/{record_id}") for record_id in record_ids]


@dataclass
class TechnitiumDnsProvider:
    """Read authoritative DNS zones through the maintained Technitium client."""

    base_url: str
    token: str
    node: str | None = None
    verify_tls: bool = True
    name: str = "technitium"

    def _client(self):
        # Keep this import local so a missing optional runtime dependency yields a
        # useful connector error instead of preventing the web application from
        # starting. It is installed through the project dependency declaration.
        try:
            from technitiumdns import Client
        except ImportError as exc:  # pragma: no cover - packaging safeguard.
            raise ProviderError("Le paquet technitiumdns-api n'est pas installé.") from exc
        return Client(
            self.base_url,
            token=self.token,
            node=self.node,
            verify_ssl=self.verify_tls,
            timeout=30,
            # The client uses Authorization: Bearer. Do not also put the secret
            # in the URL, which could otherwise be retained in proxy logs.
            send_token_in_query=False,
        )

    def list_domains(self) -> list[RemoteDomain]:
        zones: list[Any] = []
        try:
            with self._client() as api:
                page = 1
                while True:
                    batch = api.zones.list(page_number=page, zones_per_page=100)
                    zones.extend(batch)
                    # The client unwraps the response envelope, so an incomplete
                    # page is the portable end-of-list signal across server versions.
                    if len(batch) < 100:
                        break
                    page += 1
        except Exception as exc:
            raise ProviderError(f"Technitium a refusé la liste des zones: {exc}") from exc

        items: list[RemoteDomain] = []
        for zone in zones:
            raw = dict(getattr(zone, "raw", {}) or {})
            zone_name = str(getattr(zone, "name", raw.get("name", ""))).rstrip(".")
            if not zone_name:
                raise ProviderError("Technitium a renvoyé une zone sans nom.")
            zone_type = getattr(zone, "type", raw.get("type"))
            disabled = bool(getattr(zone, "disabled", raw.get("disabled", False)))
            items.append(RemoteDomain(
                provider=self.name,
                external_id=zone_name.lower(),
                name=zone_name,
                remote_status="disabled" if disabled else (zone_type or "active"),
                metadata={"node": self.node, **raw},
            ))
        return items

    def list_dns_records(self, zone_name: str) -> list[dict[str, Any]]:
        try:
            with self._client() as api:
                records = api.zones.get_records(domain=zone_name, zone=zone_name, list_zone=True)
        except Exception as exc:
            raise ProviderError(f"Technitium a refusé la lecture de la zone {zone_name}: {exc}") from exc
        return [dict(getattr(record, "raw", {}) or {}) for record in records]


@dataclass
class NginxInstanceManagerProvider:
    """Read managed NGINX instance inventory from the native NIM REST API."""

    base_url: str
    api_version: str = "v2"
    bearer_token: str | None = None
    username: str | None = None
    password: str | None = None
    verify_tls: bool = True
    name: str = "nginx_nim"

    def _authorization(self) -> str:
        if self.bearer_token:
            return f"Bearer {self.bearer_token}"
        if self.username and self.password:
            credentials = f"{self.username}:{self.password}".encode("utf-8")
            return "Basic " + base64.b64encode(credentials).decode("ascii")
        raise ProviderError("NGINX Instance Manager requiert un JWT ou un couple utilisateur/mot de passe.")

    def _get_instances_page(self, page_token: str | None = None) -> dict[str, Any] | list[Any]:
        query: dict[str, str | int] = {"pageSize": 100}
        if page_token:
            query["pageToken"] = page_token
        url = (
            f"{self.base_url.rstrip('/')}/api/platform/{self.api_version.strip('/')}/instances"
            f"?{urlencode(query)}"
        )
        request = Request(url, headers={"Authorization": self._authorization(), "Accept": "application/json"})
        context = None if self.verify_tls else ssl._create_unverified_context()
        try:
            with urlopen(request, timeout=30, context=context) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise ProviderError(f"NGINX Instance Manager a refusé la lecture des instances (HTTP {exc.code}): {detail}") from exc
        except (URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise ProviderError(f"Lecture NGINX Instance Manager impossible: {exc}") from exc

    @staticmethod
    def _instances(payload: dict[str, Any] | list[Any]) -> list[dict[str, Any]]:
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        for key in ("items", "instances", "data", "results"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        raise ProviderError("Réponse NGINX Instance Manager inattendue: liste d'instances absente.")

    @staticmethod
    def _next_page_token(payload: dict[str, Any] | list[Any]) -> str | None:
        if not isinstance(payload, dict):
            return None
        pagination = payload.get("pagination")
        candidates = (
            payload.get("nextPageToken"),
            payload.get("next_page_token"),
            pagination.get("nextPageToken") if isinstance(pagination, dict) else None,
        )
        return next((str(value) for value in candidates if value), None)

    @staticmethod
    def _instance_name(instance: dict[str, Any], external_id: str) -> str:
        system = instance.get("system") if isinstance(instance.get("system"), dict) else {}
        for value in (
            instance.get("hostname"), instance.get("hostName"), instance.get("fqdn"),
            system.get("hostname"), system.get("hostName"), system.get("fqdn"),
            instance.get("name"), system.get("name"), instance.get("address"),
        ):
            if isinstance(value, str) and value.strip():
                return value.strip().rstrip(".")
        return external_id

    def list_domains(self) -> list[RemoteDomain]:
        instances: list[dict[str, Any]] = []
        page_token: str | None = None
        while True:
            payload = self._get_instances_page(page_token)
            instances.extend(self._instances(payload))
            page_token = self._next_page_token(payload)
            if not page_token:
                break

        items: list[RemoteDomain] = []
        for instance in instances:
            external_id = str(instance.get("id") or instance.get("uid") or instance.get("instanceId") or "")
            if not external_id:
                raise ProviderError("NGINX Instance Manager a renvoyé une instance sans identifiant.")
            items.append(RemoteDomain(
                provider=self.name,
                external_id=external_id,
                name=self._instance_name(instance, external_id),
                remote_status=instance.get("status") or instance.get("state") or instance.get("health") or "managed",
                # NIM does not authoritatively manage DNS. Mark its inventory so
                # the interface and comparison API do not treat it as a DNS zone.
                metadata={"inventory_kind": "nginx_instance", **instance},
            ))
        return items
