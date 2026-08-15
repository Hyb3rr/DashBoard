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

def refresh_list(conn, name: str, category: str | None = None, url: str | None = None, cache_dir: Path | None = None) -> dict:
    category = category or DEFAULT_LISTS.get(name, "threat")
    url = url or f"https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/{name}.ipset"
    cache_dir = cache_dir or Path(os.getenv("FIREHOL_CACHE_DIR", "data/firehol")); cache = cache_dir / f"{name}.txt"
    try: result=conditional_fetch(url, cache)
    except Exception as exc: return {"status":"failed", "error":f"{type(exc).__name__}: {exc}", "records_upserted":0}
    networks=parse_networks(result["payload"])
    if not networks: return {"status":"failed", "error":"empty or invalid payload", "records_upserted":0}
    now=datetime.now(timezone.utc).isoformat(); conn.execute("UPDATE threat_indicators SET active=0 WHERE source=?", (f"firehol:{name}",))
    for network in networks:
        conn.execute("""INSERT INTO threat_indicators(network,source,category,confidence,checked_at,evidence_json,active) VALUES(?,?,?,?,?,?,1)
          ON CONFLICT(network,source,category) DO UPDATE SET checked_at=excluded.checked_at,active=1,evidence_json=excluded.evidence_json""",
          (network,f"firehol:{name}",category,1.0,now,'{}'))
    conn.commit(); return {"status":result["status"],"records_upserted":len(networks)}
