from __future__ import annotations

import os
from pathlib import Path
from datetime import datetime, timezone

from .common import atomic_write, conditional_fetch, parse_networks


def refresh_cidr_source(conn, source: str, url: str, kind: str, cache: Path | None = None) -> dict:
    cache = cache or Path(os.getenv(f"{source.upper()}_CACHE", f"data/{source}.txt"))
    result = conditional_fetch(url, cache)
    networks = parse_networks(result["payload"])
    if not networks:
        return {"status": "failed", "error": "empty or invalid CIDR payload", "records_upserted": 0}
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("UPDATE privacy_networks SET active=0 WHERE source=? AND kind=?", (source, kind))
    conn.executemany("""INSERT INTO privacy_networks(network,kind,source,first_seen,last_seen,checked_at,metadata_json,active)
      VALUES(?,?,?,?,?,?,?,1) ON CONFLICT(source,kind,network) DO UPDATE SET last_seen=excluded.last_seen,checked_at=excluded.checked_at,active=1""",
      [(network, kind, source, now, now, now, "{}") for network in networks])
    conn.executemany("INSERT INTO privacy_network_history(network,kind,source,first_seen,last_seen,observed_at,metadata_json) VALUES(?,?,?,?,?,?,?)",
                     [(network, kind, source, now, now, now, "{}") for network in networks])
    conn.commit()
    return {"status": result["status"], "records_upserted": len(networks), "cache": str(cache)}
