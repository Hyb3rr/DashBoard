"""Cloudflare anycast ranges: hosting/CDN signal, never VPN signal."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from .common import conditional_fetch, parse_networks


def refresh(conn, url: str | None = None, cache: Path | None = None) -> dict:
    url = url or os.getenv("CLOUDFLARE_IPS_URL", "https://api.cloudflare.com/client/v4/ips")
    cache = cache or Path(os.getenv("CLOUDFLARE_CACHE", "data/cloudflare_ips.json"))
    try:
        result = conditional_fetch(url, cache)
        payload = json.loads(result["payload"].decode("utf-8"))
        ranges = payload.get("result", {})
        networks = list(dict.fromkeys(parse_networks("\n".join(
            list(ranges.get("ipv4_cidrs", [])) + list(ranges.get("ipv6_cidrs", []))
        ))))
    except Exception as exc:
        return {"status": "failed", "error": f"{type(exc).__name__}: {exc}", "records_upserted": 0}
    if not networks:
        return {"status": "failed", "error": "empty Cloudflare IP payload", "records_upserted": 0}
    now = datetime.now(timezone.utc).isoformat()
    source = "cloudflare_datacenter"
    conn.execute("UPDATE privacy_networks SET active=0 WHERE source=? AND kind='datacenter'", (source,))
    for network in networks:
        conn.execute("""INSERT INTO privacy_networks(network,kind,provider,source,first_seen,last_seen,checked_at,metadata_json,active)
          VALUES(?,?,?,?,?,?,?,?,1)
          ON CONFLICT(source,kind,network) DO UPDATE SET last_seen=excluded.last_seen,checked_at=excluded.checked_at,active=1""",
          (network, "datacenter", "Cloudflare", source, now, now, now, '{"role":"cdn/hosting"}'))
        conn.execute("INSERT INTO privacy_network_history(network,kind,provider,source,first_seen,last_seen,observed_at,metadata_json) VALUES(?,?,?,?,?,?,?,?)",
                     (network, "datacenter", "Cloudflare", source, now, now, now, '{"role":"cdn/hosting"}'))
    conn.commit()
    return {"status": result["status"], "records_upserted": len(networks), "source": source}
