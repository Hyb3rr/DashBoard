"""PostgreSQL-native intelligence refresh boundary.

Network fetching/parsing stays in the existing provider modules.  This module
owns only PostgreSQL persistence, so split/live mode never needs SQLite for a
feed refresh.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import os
import socket
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

from psycopg.types.json import Jsonb

from .common import conditional_fetch, parse_networks
from .firehol import list_url, DEFAULT_LISTS, FIREHOL_SOURCES
from .global_geo import parse_rir_delegated, parse_geofeed


def _now():
    """Return the current timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def _many(conn, sql, rows):
    """Execute a parameterized batch through one PostgreSQL cursor."""
    with conn.cursor() as cur:
        cur.executemany(sql, rows)


def _json(value):
    """Wrap decoded or serialized JSON data in a PostgreSQL JSONB adapter."""
    return Jsonb(value if not isinstance(value, str) else json.loads(value))


def _provider_privacy_changes(current, incoming, now, source, kind, provider_filter, refresh_id):
    """Build provider-scoped history rows for changed membership state."""
    history_rows = []
    for network, new_state in incoming.items():
        old = current.get(network)
        if old is None:
            change_type, old_state = "added", None
        elif not old["active"]:
            change_type, old_state = "reactivated", dict(old)
        elif any(old[key] != new_state[key] for key in ("provider", "proxy_type", "score", "metadata")):
            change_type, old_state = "changed", dict(old)
        else:
            continue
        history_rows.append((now, source, kind, provider_filter, network, change_type,
                             Jsonb(old_state) if old_state else None, Jsonb(new_state), refresh_id))
    for network, old in current.items():
        if old["active"] and network not in incoming:
            history_rows.append((now, source, kind, provider_filter, network, "removed",
                                 Jsonb(dict(old)), None, refresh_id))
    return history_rows


def _apply_provider_privacy_snapshot(conn, source, kind, networks, provider,
                                     proxy_type, score, metadata, provider_filter):
    """Apply one provider snapshot without affecting sibling providers."""
    now = _now()
    current_rows = conn.execute(
        """SELECT network::text,provider,proxy_type,score,metadata,active
           FROM privacy_networks WHERE source=%s AND kind=%s AND provider=%s""",
        (source, kind, provider_filter),
    ).fetchall()
    current = {
        row[0]: {"network": row[0], "provider": row[1], "proxy_type": row[2],
                 "score": row[3], "metadata": row[4], "active": row[5]}
        for row in current_rows
    }
    incoming = {
        str(ipaddress.ip_network(network, strict=False)): {
            "provider": provider, "proxy_type": proxy_type, "score": score,
            "metadata": metadata or {}, "active": True,
        }
        for network in networks
    }
    history_rows = _provider_privacy_changes(
        current, incoming, now, source, kind, provider_filter, str(uuid.uuid4())
    )
    if history_rows:
        _many(conn, """INSERT INTO privacy_provider_change_history
          (changed_at,source,kind,provider,network,change_type,old_state,new_state,refresh_id)
          VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)""", history_rows)
    conn.execute("UPDATE privacy_networks SET active=false WHERE source=%s AND kind=%s AND provider=%s",
                 (source, kind, provider_filter))
    values = [(n, kind, provider, proxy_type, score, source, now, now, now, Jsonb(metadata or {})) for n in networks]
    _many(conn, """INSERT INTO privacy_networks
      (network,kind,provider,proxy_type,score,source,first_seen,last_seen,checked_at,metadata,active)
      VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,true)
      ON CONFLICT(source,kind,network) DO UPDATE SET provider=excluded.provider,
       proxy_type=excluded.proxy_type,score=excluded.score,last_seen=excluded.last_seen,
       checked_at=excluded.checked_at,metadata=excluded.metadata,active=true
      WHERE privacy_networks.active IS DISTINCT FROM true OR
         (privacy_networks.provider,privacy_networks.proxy_type,privacy_networks.score,privacy_networks.metadata)
         IS DISTINCT FROM (excluded.provider,excluded.proxy_type,excluded.score,excluded.metadata)""", values)


def _privacy(conn, source, kind, networks, *, provider=None, proxy_type=None, score=None, metadata=None, provider_filter=None):
    """Persist one privacy snapshot using global or provider-scoped semantics."""
    if provider_filter is not None:
        return _apply_provider_privacy_snapshot(
            conn, source, kind, networks, provider, proxy_type, score, metadata, provider_filter
        )
    from .snapshot_diff import SnapshotRejected, apply_privacy_snapshot
    now = _now()
    result = apply_privacy_snapshot(
        conn,
        source,
        kind,
        [
            (network, kind, provider, proxy_type, score, source,
             now, now, now, Jsonb(metadata or {}))
            for network in networks
        ],
        history=True,
    )
    if result.get("status") != "updated":
        raise SnapshotRejected(result)
    return result


def _threat(conn, source, category, networks):
    """Replace current threat memberships for one source and category."""
    now = _now()
    conn.execute("UPDATE threat_indicators SET active=false WHERE source=%s AND category=%s", (source, category))
    _many(conn, """INSERT INTO threat_indicators
      (network,source,category,confidence,first_seen,last_seen,checked_at,evidence,active)
      VALUES(%s,%s,%s,1.0,%s,%s,%s,%s,true)
      ON CONFLICT(network,source,category) DO UPDATE SET confidence=excluded.confidence,
       last_seen=excluded.last_seen,checked_at=excluded.checked_at,evidence=excluded.evidence,active=true""",
      [(n, source, category, now, now, now, Jsonb({})) for n in networks])


def refresh_cidr(conn, source, url, kind, cache=None):
    """Fetch, validate and persist one privacy CIDR feed."""
    cache = cache or Path(os.getenv(f"{source.upper()}_CACHE", f"data/{source}.txt"))
    result = conditional_fetch(url, cache)
    networks = parse_networks(result["payload"])
    if not networks:
        return {"status": "failed", "error": "empty or invalid CIDR payload", "records_upserted": 0}
    _privacy(conn, source, kind, networks)
    return {"status": result["status"], "records_upserted": len(networks), "cache": str(cache)}


def refresh_firehol(conn, name, category=None, url=None, cache_dir=None):
    """Refresh a FireHOL feed into threat and optional privacy snapshots."""
    category = category or DEFAULT_LISTS.get(name, "threat")
    url = url or list_url(name)
    if url == list_url(name) and not FIREHOL_SOURCES.get(name, {}).get("enabled", True):
        return {"status": "unavailable", "error": "feed disabled or unpublished", "records_upserted": 0, "url": url}
    cache = (cache_dir or Path(os.getenv("FIREHOL_CACHE_DIR", "data/firehol"))) / f"{name}.txt"
    result = conditional_fetch(url, cache)
    networks = parse_networks(result["payload"])
    if not networks:
        return {"status": "failed", "error": "empty or invalid payload", "records_upserted": 0, "url": url}
    source = f"firehol:{name}"
    from .snapshot_diff import SnapshotRejected, apply_privacy_snapshot, apply_threat_snapshot

    threat_result = apply_threat_snapshot(conn, source, category, networks)
    if threat_result.get("status") != "updated":
        raise SnapshotRejected(threat_result)
    privacy_result = None
    if name in {"firehol_proxies", "firehol_anonymous"}:
        now = _now()
        privacy_rows = [
            (network, "proxy", "FireHOL", "datacenter", None, source,
             now, now, now, Jsonb({"role": "proxy"}))
            for network in networks
        ]
        privacy_result = apply_privacy_snapshot(conn, source, "proxy", privacy_rows, history=True)
        if privacy_result.get("status") != "updated":
            raise SnapshotRejected(privacy_result)
    return {"status": result["status"], "url": url, "records_upserted": len(networks),
            "threat": threat_result, "privacy": privacy_result}


def refresh_cloudflare(conn, url=None, cache=None):
    """Fetch and persist Cloudflare IPv4/IPv6 datacenter ranges."""
    import json as _jsonlib
    url = url or os.getenv("CLOUDFLARE_IPS_URL", "https://api.cloudflare.com/client/v4/ips")
    cache = cache or Path(os.getenv("CLOUDFLARE_CACHE", "data/cloudflare_ips.json"))
    result = conditional_fetch(url, cache)
    payload = _jsonlib.loads(result["payload"].decode("utf-8"))
    ranges = payload.get("result", {})
    networks = parse_networks("\n".join(list(ranges.get("ipv4_cidrs", [])) + list(ranges.get("ipv6_cidrs", []))))
    if not networks:
        return {"status": "failed", "error": "empty Cloudflare IP payload", "records_upserted": 0}
    _privacy(conn, "cloudflare_datacenter", "datacenter", networks, provider="Cloudflare", metadata={"role": "cdn/hosting"})
    return {"status": result["status"], "records_upserted": len(networks), "source": "cloudflare_datacenter"}


def refresh_rir(conn, rir, url, cache=None):
    """Fetch and persist a delegated registry prefix snapshot."""
    cache = cache or Path(os.getenv(f"{rir.upper()}_DELEGATED_CACHE", f"data/geo/{rir.lower()}-delegated.txt"))
    result = conditional_fetch(url, cache)
    rows = parse_rir_delegated(result["payload"].decode("utf-8", "replace"), rir)
    if not rows:
        return {"status": "failed", "error": "empty or invalid RIR payload", "records_upserted": 0}
    source = f"rir:{rir.lower()}"
    from .snapshot_diff import SnapshotRejected, apply_geo_snapshot
    snapshot = apply_geo_snapshot(conn, source, [
        {"network": r["network"], "rir": rir, "country_code": r["country_code"], "metadata": {}}
        for r in rows
    ])
    if snapshot.get("status") != "updated":
        raise SnapshotRejected(snapshot)
    return {"status": result["status"], "records_upserted": len(rows),
            "source": source, "snapshot": snapshot}


def refresh_geofeed(conn, name, url, cache=None):
    """Fetch and persist geofeed prefixes and location observations."""
    cache = cache or Path(os.getenv(f"GEOFEED_{name.upper()}_CACHE", f"data/geo/geofeed-{name}.csv"))
    result = conditional_fetch(url, cache)
    rows = parse_geofeed(result["payload"].decode("utf-8", "replace"))
    if not rows:
        return {"status": "failed", "error": "empty or invalid geofeed", "records_upserted": 0}
    source = f"geofeed:{name}"
    now = _now()
    _many(conn, """INSERT INTO geo_prefixes(network,source,first_seen,last_seen,active,metadata)
      VALUES(%s,%s,%s,%s,true,%s)
      ON CONFLICT(network,source) DO UPDATE SET last_seen=excluded.last_seen,active=true,metadata=excluded.metadata""",
      [(r["network"], source, now, now, Jsonb({"distribution": name, "evidence_type": "geofeed"})) for r in rows])
    _many(conn, """INSERT INTO geo_location_observations
      (network,country_code,source,source_confidence,location_scope,city,observed_at,metadata)
      VALUES(%s,%s,%s,95,'network',%s,now(),%s)
      ON CONFLICT(network,source) DO UPDATE SET country_code=excluded.country_code,
       source_confidence=excluded.source_confidence,city=excluded.city,observed_at=excluded.observed_at,metadata=excluded.metadata""",
      [(r["network"], r["country_code"], source, r.get("city"), Jsonb({
          "provider": "network_operator", "distribution": name,
          "evidence_type": "geofeed", "standard": "RFC9632/RFC8805",
          "prefix": r["network"], "region": r.get("region"), "city": r.get("city")})) for r in rows])
    return {"status": result["status"], "records_upserted": len(rows), "source": source}


def _addresses(value, resolve=True):
    """Normalize an IP literal or optionally resolve a hostname to addresses."""
    try:
        return [str(ipaddress.ip_address(value))]
    except ValueError:
        if not resolve:
            return []
        try:
            return list(dict.fromkeys(str(item[4][0]) for item in socket.getaddrinfo(value, None, type=socket.SOCK_STREAM)))
        except OSError:
            return []


def _values(item, key):
    """Read string values from a nested manifest field or field path."""
    value = item
    for part in key if isinstance(key, list) else [key]:
        if not isinstance(value, dict):
            return []
        value = value.get(part)
    if isinstance(value, str):
        return [value]
    return [x for x in value if isinstance(x, str)] if isinstance(value, list) else []


def refresh_az0(conn, url=None, timeout=30):
    """Refresh provider-scoped VPN address snapshots from the AZ0 manifest."""
    url = url or os.getenv("AZ0_VPN_MANIFEST_URL", "https://raw.githubusercontent.com/az0/vpn_ip/main/data/get_addresses_via_api.json")
    with urlopen(Request(url, headers={"User-Agent": "ip-intelligence/1.0"}), timeout=timeout) as response:
        manifest = json.loads(response.read().decode("utf-8"))
    providers = manifest.get("providers", manifest) if isinstance(manifest, dict) else manifest
    if not isinstance(providers, dict):
        providers = {str(i): v for i, v in enumerate(providers or [])}
    total = 0
    statuses = {}
    for name, item in providers.items():
        if not isinstance(item, dict):
            continue
        found = []
        errors = []
        for mirror in _values(item, "urls") or _values(item, "url"):
            try:
                with urlopen(Request(mirror, headers={"User-Agent": "ip-intelligence/1.0"}), timeout=timeout) as response:
                    data = json.loads(response.read().decode("utf-8"))
                found += [x for ip in _values(data, item.get("ip_key", "")) for x in _addresses(ip, False)]
                found += [x for host in _values(data, item.get("hostname_key", "")) for x in _addresses(host, True)]
                if found:
                    break
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                errors.append(f"{mirror}: {type(exc).__name__}: {exc}")
        found = list(dict.fromkeys(found))
        promoted = bool(found and not errors)
        if promoted:
            _privacy(conn, "az0_vpn_ip", "vpn", found, provider=name, provider_filter=name, metadata={"errors": errors})
            total += len(found)
        statuses[name] = {"status": "ok" if found and not errors else "partial" if found else "failed", "records": len(found), "errors": errors}
    provider_statuses = {item["status"] for item in statuses.values()}
    if "partial" in provider_statuses:
        overall = "partial"
    elif total and provider_statuses <= {"ok"}:
        overall = "updated"
    else:
        overall = "failed"
    return {"status": overall, "url": url, "records_upserted": total, "providers": statuses}


def _device_browser_records(payload, now):
    """Normalize DeviceBrowser CSV rows into privacy snapshot records."""
    records = {}
    for row in csv.DictReader(io.StringIO(payload.decode("utf-8-sig", "replace"))):
        network = (row.get("ip") or row.get("network") or row.get("ipAddress") or "").strip()
        if not network:
            continue
        try:
            network = str(ipaddress.ip_network(network, strict=False))
        except ValueError:
            try:
                network = str(ipaddress.ip_network(f"{ipaddress.ip_address(network)}/{ipaddress.ip_address(network).max_prefixlen}", strict=False))
            except ValueError:
                continue
        proxy_type = (row.get("proxyType") or row.get("proxy_type") or "").strip().lower() or None
        if (row.get("isDataCenter") or row.get("is_data_center") or "").strip().lower() == "true" or proxy_type == "data_center":
            proxy_type = "datacenter"
        try:
            score = float(row.get("score") or 0)
        except (TypeError, ValueError):
            score = 0.0
        metadata = {k: row.get(k) for k in ("asn", "organization", "country_code", "countryCode", "city", "latitude", "longitude", "isProxy", "isDataCenter") if row.get(k)}
        records[network] = (network, "proxy", None, proxy_type, score, "device_browser", now, now, now, Jsonb(metadata))
    return records


def refresh_device_browser(conn, url=None, api_key=None, cache=None):
    """Fetch, normalize, and diff a DeviceBrowser proxy-network snapshot."""
    from .device_browser_info import _csv_payload
    from .common import atomic_write
    from urllib.parse import urlparse
    url = url or os.getenv("DEVICEBROWSERINFO_CSV_URL", "").strip()
    api_key = api_key if api_key is not None else os.getenv("DEVICEBROWSERINFO_API_KEY", "")
    if not url:
        return {"status": "not_configured", "records_upserted": 0}
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    custom = os.getenv("DEVICEBROWSERINFO_AUTH_HEADER", "").strip()
    if custom and api_key:
        headers[custom] = api_key
        headers.pop("Authorization", None)
    local_path = Path(url) if not urlparse(url).scheme else None
    if local_path and local_path.is_file():
        payload = local_path.read_bytes()
    else:
        with urlopen(Request(url, headers=headers), timeout=60) as response:
            payload = response.read()
    payload = _csv_payload(payload, url)
    cache = cache or Path(os.getenv("DEVICEBROWSERINFO_CACHE", "data/device_browser_info.csv"))
    now = _now()
    parse_started = time.monotonic()
    records = _device_browser_records(payload, now)
    parse_ms = round((time.monotonic() - parse_started) * 1000, 2)
    if not records:
        return {"status": "failed", "error": "CSV contains no valid IP records", "records_upserted": 0}
    from .snapshot_diff import apply_privacy_snapshot
    result = apply_privacy_snapshot(
        conn,
        "device_browser",
        "proxy",
        records.values(),
        history=True,
    )
    if result.get("status") == "updated":
        atomic_write(cache, payload)
    result["parse_ms"] = parse_ms
    result["total_ms"] = round(result.get("total_ms", 0) + result["parse_ms"], 2)
    result["cache"] = str(cache)
    return result
