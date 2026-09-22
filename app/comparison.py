from __future__ import annotations

from collections import defaultdict
import json
from typing import Any


def _without_none(values: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in values.items() if value is not None}


def source_profile(source: dict[str, Any]) -> dict[str, Any]:
    """Expose comparable, provider-neutral information without contact details."""
    metadata = source["metadata"]
    profile: dict[str, Any] = {
        "source": f"{source['provider']}:{source['external_id']}",
        "provider": source["provider"],
        "lifecycle_status": source["lifecycle_status"],
        "remote_status": source.get("remote_status"),
        "first_seen_at": source.get("created_at"),
        "last_seen_at": source.get("last_seen_at"),
    }
    if source["provider"] == "cloudflare":
        profile.update({
            "zone_created_at": metadata.get("created_on"),
            "zone_modified_at": metadata.get("modified_on"),
            "activated_at": metadata.get("activated_on"),
            "zone_type": metadata.get("type"),
            "plan": (metadata.get("plan") or {}).get("name"),
            "nameservers": sorted(metadata.get("name_servers") or []),
            "paused": metadata.get("paused"),
        })
    elif source["provider"] == "infomaniak":
        profile.update({
            "registered_at": metadata.get("created_at"),
            "expires_at": metadata.get("expires_at"),
            "tld": metadata.get("tld"),
            "premium": metadata.get("is_premium"),
            "dnssec": (metadata.get("options") or {}).get("dnssec"),
            "dns_anycast": (metadata.get("options") or {}).get("dns_anycast"),
            "domain_privacy": (metadata.get("options") or {}).get("domain_privacy"),
        })
    elif source["provider"].startswith("windows_dns:"):
        profile.update({
            "server": metadata.get("server"),
            "zone_type": metadata.get("zone_type"),
            "ad_integrated": metadata.get("is_ds_integrated"),
            "dynamic_update": metadata.get("dynamic_update"),
            "dns_policy_count": len(metadata.get("policies") or []),
        })
    elif source["provider"].startswith("custom:"):
        profile.update({
            "declared_source": metadata.get("source"),
            "zone_type": metadata.get("zone_type"),
            "record_count": len(metadata.get("records") or []),
        })
    elif source["provider"] == "ovh":
        service_info = metadata.get("service_info") or {}
        profile.update({
            "domain_created_at": service_info.get("creation"),
            "expires_at": service_info.get("expiration"),
            "service_status": service_info.get("status"),
            "nameserver_mode": metadata.get("nameServerType"),
            "transfer_lock": metadata.get("transferLockStatus"),
            "offer": metadata.get("offer"),
            "dnssec_supported": metadata.get("dnssecSupported"),
        })
    return _without_none(profile)


def normalize_record(provider: str, record: dict[str, Any], domain_name: str) -> dict[str, Any] | None:
    """Bring Cloudflare and Infomaniak record shapes to the same DNS vocabulary."""
    if provider == "cloudflare":
        owner, value = record.get("name"), record.get("content")
        extra = {"proxied": record.get("proxied"), "comment": record.get("comment")}
    elif provider == "infomaniak":
        owner, value = record.get("source"), record.get("target")
        extra = {}
    elif provider.startswith("windows_dns:"):
        owner, value = record.get("name"), record.get("value")
        extra = {}
    elif provider.startswith("custom:"):
        owner, value = record.get("name"), record.get("value")
        extra = {
            "priority": record.get("priority"),
            "weight": record.get("weight"),
            "port": record.get("port"),
        }
    elif provider == "ovh":
        owner, value = record.get("subDomain"), record.get("target")
        record_type = record.get("fieldType")
        extra = {}
        if owner in {None, ""}:
            owner = "@"
    else:
        return None
    if provider != "ovh":
        record_type = record.get("type")
    if not owner or value is None or not record_type:
        return None
    owner = str(owner).rstrip(".").lower()
    apex = domain_name.rstrip(".").lower()
    if owner in {"@", ""}:
        owner = apex
    elif "." not in owner:
        owner = f"{owner}.{apex}"
    return _without_none({
        "name": owner,
        "type": str(record_type).upper(),
        "value": str(value).rstrip(".") if str(record_type).upper() not in {"TXT", "CAA"} else str(value),
        "ttl": record.get("ttl"),
        **extra,
    })


def records_from_metadata(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the full DNS configuration stored by a source snapshot."""
    records = metadata.get("dns_records", metadata.get("records", []))
    return records if isinstance(records, list) else []


def compare_source_snapshots(
    *,
    domain_name: str,
    provider: str,
    before: dict[str, Any],
    after: dict[str, Any],
) -> dict[str, Any]:
    """Compare two stored states of one provider source.

    DNS records are compared as complete owner/type groups, which makes a TTL,
    target, proxy flag, or provider-specific option change visible as a change
    instead of presenting it as an unrelated deletion and creation.
    """
    def normalized(metadata: dict[str, Any]) -> dict[tuple[str, str], list[dict[str, Any]]]:
        groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for record in records_from_metadata(metadata):
            value = normalize_record(provider, record, domain_name)
            if value is not None:
                groups[(value["name"], value["type"])].append(value)
        return {
            key: sorted(records, key=lambda record: json.dumps(record, sort_keys=True, ensure_ascii=False))
            for key, records in groups.items()
        }

    before_records, after_records = normalized(before), normalized(after)
    added = [record for key in sorted(set(after_records) - set(before_records)) for record in after_records[key]]
    removed = [record for key in sorted(set(before_records) - set(after_records)) for record in before_records[key]]
    changed = [
        {"name": key[0], "type": key[1], "before": before_records[key], "after": after_records[key]}
        for key in sorted(set(before_records) & set(after_records))
        if before_records[key] != after_records[key]
    ]
    ignored = {"dns_records", "records", "dns_records_error"}
    configuration_changes = [
        {"field": field, "before": before.get(field), "after": after.get(field)}
        for field in sorted((set(before) | set(after)) - ignored)
        if before.get(field) != after.get(field)
    ]
    return {
        "records": {"added": added, "removed": removed, "changed": changed},
        "configuration_changes": configuration_changes,
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "configuration_changed": len(configuration_changes),
        },
    }


def compare(domain: dict[str, Any], records_by_source: dict[str, list[dict[str, Any]]], errors: dict[str, str]) -> dict[str, Any]:
    profiles = [source_profile(source) for source in domain["sources"]]
    normalized: dict[str, list[dict[str, Any]]] = {}
    for source in domain["sources"]:
        key = f"{source['provider']}:{source['external_id']}"
        normalized[key] = [
            normalized_record
            for record in records_by_source.get(key, [])
            if (normalized_record := normalize_record(source["provider"], record, domain["name"])) is not None
        ]

    record_locations: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    groups: dict[tuple[str, str], dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    for source_key, records in normalized.items():
        for record in records:
            record_locations[(record["name"], record["type"], record["value"])].add(source_key)
            groups[(record["name"], record["type"])][source_key].append(record)

    readable_sources = list(normalized)
    all_sources = set(readable_sources)
    common = [
        {"name": name, "type": record_type, "value": value}
        for (name, record_type, value), locations in sorted(record_locations.items())
        if all_sources and locations == all_sources
    ]
    only_by_source = {
        source_key: [
            {"name": name, "type": record_type, "value": value}
            for (name, record_type, value), locations in sorted(record_locations.items())
            if source_key in locations and locations != all_sources
        ]
        for source_key in readable_sources
    }
    conflicts = [
        {
            "name": name,
            "type": record_type,
            "sources": {source_key: entries for source_key, entries in source_entries.items()},
        }
        for (name, record_type), source_entries in sorted(groups.items())
        if len(source_entries) > 1 and len({tuple((item["value"], item.get("ttl"), item.get("proxied"), item.get("priority"), item.get("weight"), item.get("port")) for item in entries) for entries in source_entries.values()}) > 1
    ]
    return {
        "domain": domain["name"],
        "source_count": len(domain["sources"]),
        "profiles": profiles,
        "dns": {
            "sources_read": readable_sources,
            "errors": errors,
            "common_records": common,
            "only_by_source": only_by_source,
            "conflicts": conflicts,
            "summary": {
                "common": len(common),
                "different": sum(len(records) for records in only_by_source.values()),
                "conflicts": len(conflicts),
            },
        },
    }
