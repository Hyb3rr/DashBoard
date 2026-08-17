from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from .common import conditional_fetch, parse_networks

DEFAULT_LISTS = {
 "firehol_proxies":"proxy", "firehol_anonymous":"anonymous", "dm_tor":"tor", "et_tor":"tor",
 "firehol_webserver":"webserver", "abuseipdb_1d":"abuse", "abuseipdb_30d":"abuse",
 "dshield":"scanner", "feodo":"malware", "dronebl_auto_botnets":"botnet", "sslbl":"malware", "zeus":"malware", "palevo":"malware",
}

# FireHOL distinguishes individual-IP ipsets from CIDR/netset feeds. Using
# .ipset for every list makes the proxy/anonymous/webserver feeds 404.
NETSET_LISTS = {
    "firehol_proxies", "firehol_anonymous", "firehol_webserver",
    "dshield", "dshield_1d", "dshield_30d", "dshield_7d",
    "dronebl_auto_botnets",
}

# Keep the logical source name separate from the repository filename. Disabled
# upstream feeds remain visible in health output but are not requested every run.
FIREHOL_SOURCES = {
    name: {"url": f"https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/{name}{'.netset' if name in NETSET_LISTS else '.ipset'}", "enabled": name not in {"sslbl", "zeus", "palevo"}}
    for name in DEFAULT_LISTS
}

def list_url(name: str) -> str:
    """Return the official FireHOL feed URL for a list name."""
    return FIREHOL_SOURCES.get(name, {}).get("url") or f"https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/{name}{'.netset' if name in NETSET_LISTS else '.ipset'}"


def refresh_list(conn, name: str, category: str | None = None, url: str | None = None, cache_dir: Path | None = None) -> dict:
    category = category or DEFAULT_LISTS.get(name, "threat")
    url = url or list_url(name)
    if url == list_url(name) and not FIREHOL_SOURCES.get(name, {}).get("enabled", True):
        return {"status": "unavailable", "error": "feed disabled or no longer published upstream", "url": url, "records_upserted": 0}
    cache_dir = cache_dir or Path(os.getenv("FIREHOL_CACHE_DIR", "data/firehol")); cache = cache_dir / f"{name}.txt"
    try:
        result = conditional_fetch(url, cache)
    except Exception as exc:
        return {"status": "failed", "error": f"{type(exc).__name__}: {exc}", "url": url, "records_upserted": 0}
    networks=parse_networks(result["payload"])
    if not networks:
        return {"status": "failed", "error": "empty or invalid payload", "url": url, "records_upserted": 0}
    now=datetime.now(timezone.utc).isoformat(); source=f"firehol:{name}"
    conn.execute("UPDATE threat_indicators SET active=0 WHERE source=?", (source,))
    privacy_kind = "proxy" if name in {"firehol_proxies", "firehol_anonymous"} else None
    if privacy_kind:
        conn.execute("UPDATE privacy_networks SET active=0 WHERE source=? AND kind=?", (source, privacy_kind))
    conn.executemany("""INSERT INTO threat_indicators(network,source,category,confidence,checked_at,evidence_json,active) VALUES(?,?,?,?,?,?,1)
      ON CONFLICT(network,source,category) DO UPDATE SET checked_at=excluded.checked_at,active=1,evidence_json=excluded.evidence_json""",
      [(network, source, category, 1.0, now, "{}") for network in networks])
    if privacy_kind:
        conn.executemany("""INSERT INTO privacy_networks
          (network,kind,provider,proxy_type,source,first_seen,last_seen,checked_at,metadata_json,active)
          VALUES(?,?,?,?,?,?,?,?,?,1)
          ON CONFLICT(source,kind,network) DO UPDATE SET last_seen=excluded.last_seen,checked_at=excluded.checked_at,active=1""",
          [(network, privacy_kind, "FireHOL", "datacenter", source, now, now, now, '{"role":"proxy"}') for network in networks])
    conn.commit(); return {"status": result["status"], "url": url, "records_upserted": len(networks)}
