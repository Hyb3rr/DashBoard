from __future__ import annotations

import csv
import io
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from .common import atomic_write
from urllib.request import Request, urlopen


def refresh(conn, url: str | None = None, api_key: str | None = None, cache: Path | None = None) -> dict:
    url = url or os.getenv("DEVICEBROWSERINFO_CSV_URL", "").strip()
    api_key = api_key if api_key is not None else os.getenv("DEVICEBROWSERINFO_API_KEY", "")
    if not url: return {"status": "not_configured", "records_upserted": 0}
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    custom = os.getenv("DEVICEBROWSERINFO_AUTH_HEADER", "").strip()
    if custom and api_key: headers[custom] = api_key; headers.pop("Authorization", None)
    with urlopen(Request(url, headers=headers), timeout=60) as response: payload = response.read()
    cache = cache or Path(os.getenv("DEVICEBROWSERINFO_CACHE", "data/device_browser_info.csv"))
    atomic_write(cache, payload)  # parse only after durable atomic replacement
    rows = csv.DictReader(io.StringIO(payload.decode("utf-8-sig", "replace")))
    now = datetime.now(timezone.utc).isoformat(); count=0
    conn.execute("UPDATE privacy_networks SET active=0 WHERE source='device_browser' AND kind='proxy'")
    for row in rows:
        network = (row.get("ip") or row.get("network") or row.get("ipAddress") or "").strip()
        if not network: continue
        proxy_type = (row.get("proxyType") or row.get("proxy_type") or "").strip().lower() or None
        if proxy_type == "data_center": proxy_type = "datacenter"
        metadata = {k: row.get(k) for k in ("asn", "country", "countryCode", "city", "latitude", "longitude") if row.get(k)}
        conn.execute("""INSERT INTO privacy_networks(network,kind,provider,proxy_type,score,source,first_seen,last_seen,checked_at,metadata_json,active)
          VALUES(?,?,?,?,?,?,?,?,?,?,1) ON CONFLICT(source,kind,network) DO UPDATE SET proxy_type=excluded.proxy_type,score=excluded.score,last_seen=excluded.last_seen,checked_at=excluded.checked_at,metadata_json=excluded.metadata_json,active=1""",
          (network,"proxy",None,proxy_type,float(row.get("score") or 0),"device_browser",row.get("firstSeenAt") or now,row.get("lastSeenAt") or now,now,json.dumps(metadata)))
        conn.execute("INSERT INTO privacy_network_history(network,kind,provider,proxy_type,score,source,first_seen,last_seen,observed_at,metadata_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
                     (network, "proxy", None, proxy_type, float(row.get("score") or 0), "device_browser", row.get("firstSeenAt") or now, row.get("lastSeenAt") or now, now, json.dumps(metadata)))
        count += 1
    conn.commit(); return {"status":"updated", "records_upserted":count, "cache":str(cache)}
