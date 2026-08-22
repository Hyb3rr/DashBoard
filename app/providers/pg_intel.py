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
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

from psycopg.types.json import Jsonb

from .common import conditional_fetch, parse_networks
from .firehol import list_url, DEFAULT_LISTS, NETSET_LISTS, FIREHOL_SOURCES
from .global_geo import parse_rir_delegated, parse_geofeed
from . import vpn_az0


def _now():
    return datetime.now(timezone.utc)


def _many(conn, sql, rows):
    with conn.cursor() as cur:
        cur.executemany(sql, rows)


def _json(value):
    return Jsonb(value if not isinstance(value, str) else json.loads(value))


def _privacy(conn, source, kind, networks, *, provider=None, proxy_type=None, score=None, metadata=None, provider_filter=None):
    now = _now()
    if provider_filter is None:
        conn.execute("UPDATE privacy_networks SET active=false WHERE source=%s AND kind=%s", (source, kind))
    else:
        conn.execute("UPDATE privacy_networks SET active=false WHERE source=%s AND kind=%s AND provider=%s", (source, kind, provider_filter))
    values = [(n, kind, provider, proxy_type, score, source, now, now, now, Jsonb(metadata or {})) for n in networks]
    _many(conn, """INSERT INTO privacy_networks
      (network,kind,provider,proxy_type,score,source,first_seen,last_seen,checked_at,metadata,active)
      VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,true)
      ON CONFLICT(source,kind,network) DO UPDATE SET provider=excluded.provider,
       proxy_type=excluded.proxy_type,score=excluded.score,last_seen=excluded.last_seen,
       checked_at=excluded.checked_at,metadata=excluded.metadata,active=true""", values)
    if values:
        _many(conn, """INSERT INTO privacy_network_history
          (network,kind,provider,proxy_type,score,source,first_seen,last_seen,observed_at,metadata)
          VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
          [(n, kind, provider, proxy_type, score, source, now, now, now, Jsonb(metadata or {})) for n in networks])


def _threat(conn, source, category, networks):
    now = _now()
    conn.execute("UPDATE threat_indicators SET active=false WHERE source=%s AND category=%s", (source, category))
    _many(conn, """INSERT INTO threat_indicators
      (network,source,category,confidence,first_seen,last_seen,checked_at,evidence,active)
      VALUES(%s,%s,%s,1.0,%s,%s,%s,%s,true)
      ON CONFLICT(network,source,category) DO UPDATE SET confidence=excluded.confidence,
       last_seen=excluded.last_seen,checked_at=excluded.checked_at,evidence=excluded.evidence,active=true""",
      [(n, source, category, now, now, now, Jsonb({})) for n in networks])


def refresh_cidr(conn, source, url, kind, cache=None):
    cache = cache or Path(os.getenv(f"{source.upper()}_CACHE", f"data/{source}.txt"))
    result = conditional_fetch(url, cache)
    networks = parse_networks(result["payload"])
    if not networks:
        return {"status": "failed", "error": "empty or invalid CIDR payload", "records_upserted": 0}
    _privacy(conn, source, kind, networks)
    return {"status": result["status"], "records_upserted": len(networks), "cache": str(cache)}


def refresh_firehol(conn, name, category=None, url=None, cache_dir=None):
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
    _threat(conn, source, category, networks)
    if name in {"firehol_proxies", "firehol_anonymous"}:
        _privacy(conn, source, "proxy", networks, provider="FireHOL", proxy_type="datacenter", metadata={"role": "proxy"})
    return {"status": result["status"], "url": url, "records_upserted": len(networks)}


def refresh_cloudflare(conn, url=None, cache=None):
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
    cache = cache or Path(os.getenv(f"{rir.upper()}_DELEGATED_CACHE", f"data/geo/{rir.lower()}-delegated.txt"))
    result = conditional_fetch(url, cache)
    rows = parse_rir_delegated(result["payload"].decode("utf-8", "replace"), rir)
    if not rows:
        return {"status": "failed", "error": "empty or invalid RIR payload", "records_upserted": 0}
    now = _now(); source = f"rir:{rir.lower()}"
    conn.execute("UPDATE geo_prefixes SET active=false WHERE source=%s", (source,))
    _many(conn, """INSERT INTO geo_prefixes
      (network,rir,registration_country,source,first_seen,last_seen,active,metadata)
      VALUES(%s,%s,%s,%s,%s,%s,true,%s)
      ON CONFLICT(network,source) DO UPDATE SET rir=excluded.rir,
       registration_country=excluded.registration_country,last_seen=excluded.last_seen,
       active=true,metadata=excluded.metadata""",
      [(r["network"], rir, r["country_code"], source, now, now, Jsonb({})) for r in rows])
    return {"status": result["status"], "records_upserted": len(rows), "source": source}


def refresh_geofeed(conn, name, url, cache=None):
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
    value = item
    for part in key if isinstance(key, list) else [key]:
        if not isinstance(value, dict): return []
        value = value.get(part)
    if isinstance(value, str): return [value]
    return [x for x in value if isinstance(x, str)] if isinstance(value, list) else []


def refresh_az0(conn, url=None, timeout=30):
    url = url or os.getenv("AZ0_VPN_MANIFEST_URL", "https://raw.githubusercontent.com/az0/vpn_ip/main/data/get_addresses_via_api.json")
    with urlopen(Request(url, headers={"User-Agent": "ip-intelligence/1.0"}), timeout=timeout) as response:
        manifest = json.loads(response.read().decode("utf-8"))
    providers = manifest.get("providers", manifest) if isinstance(manifest, dict) else manifest
    if not isinstance(providers, dict): providers = {str(i): v for i, v in enumerate(providers or [])}
    total = 0; statuses = {}
    for name, item in providers.items():
        if not isinstance(item, dict): continue
        found = []; errors = []
        for mirror in _values(item, "urls") or _values(item, "url"):
            try:
                with urlopen(Request(mirror, headers={"User-Agent": "ip-intelligence/1.0"}), timeout=timeout) as response:
                    data = json.loads(response.read().decode("utf-8"))
                found += [x for ip in _values(data, item.get("ip_key", "")) for x in _addresses(ip, False)]
                found += [x for host in _values(data, item.get("hostname_key", "")) for x in _addresses(host, True)]
                if found: break
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                errors.append(f"{mirror}: {type(exc).__name__}: {exc}")
        found = list(dict.fromkeys(found))
        if found:
            _privacy(conn, "az0_vpn_ip", "vpn", found, provider=name, provider_filter=name, metadata={"errors": errors})
        total += len(found)
        statuses[name] = {"status": "ok" if found and not errors else "partial" if found else "failed", "records": len(found), "errors": errors}
    return {"status": "updated" if total else "failed", "url": url, "records_upserted": total, "providers": statuses}


def refresh_device_browser(conn, url=None, api_key=None, cache=None):
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
    now = _now(); records = {}
    for row in csv.DictReader(io.StringIO(payload.decode("utf-8-sig", "replace"))):
        network = (row.get("ip") or row.get("network") or row.get("ipAddress") or "").strip()
        if not network: continue
        try: network = str(ipaddress.ip_network(network, strict=False))
        except ValueError:
            try: network = str(ipaddress.ip_network(f"{ipaddress.ip_address(network)}/{ipaddress.ip_address(network).max_prefixlen}", strict=False))
            except ValueError: continue
        proxy_type = (row.get("proxyType") or row.get("proxy_type") or "").strip().lower() or None
        if (row.get("isDataCenter") or row.get("is_data_center") or "").strip().lower() == "true" or proxy_type == "data_center": proxy_type = "datacenter"
        try: score = float(row.get("score") or 0)
        except (TypeError, ValueError): score = 0.0
        metadata = {k: row.get(k) for k in ("asn", "organization", "country_code", "countryCode", "city", "latitude", "longitude", "isProxy", "isDataCenter") if row.get(k)}
        records[network] = (network, "proxy", None, proxy_type, score, "device_browser", now, now, now, Jsonb(metadata))
    if not records: return {"status": "failed", "error": "CSV contains no valid IP records", "records_upserted": 0}
    atomic_write(cache, payload)
    _privacy(conn, "device_browser", "proxy", list(records), provider="DeviceBrowser", metadata={"source": "device_browser"})
    conn.execute("DELETE FROM privacy_networks WHERE source='device_browser' AND kind='proxy' AND active=false")
    _many(conn, """UPDATE privacy_networks SET provider=%s,proxy_type=%s,score=%s,
      first_seen=%s,last_seen=%s,checked_at=%s,metadata=%s,active=true
      WHERE source=%s AND kind=%s AND network=%s""",
      [("DeviceBrowser", row[3], row[4], row[6], row[7], row[8], row[9], row[5], row[1], row[0]) for row in records.values()])
    return {"status": "updated", "records_upserted": len(records), "cache": str(cache)}
