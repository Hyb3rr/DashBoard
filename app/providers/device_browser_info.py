from __future__ import annotations

import csv
import io
import ipaddress
import json
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from .common import atomic_write
from urllib.request import Request, urlopen


def _csv_payload(payload: bytes, source: str) -> bytes:
    """Extract the provider CSV while rejecting unsafe/empty archives."""
    is_zip = payload[:4] == b"PK\x03\x04" or source.lower().split("?", 1)[0].endswith(".zip")
    if not is_zip:
        return payload
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        members = [item for item in archive.infolist() if not item.is_dir() and item.filename.lower().endswith(".csv")]
        safe = [item for item in members if not Path(item.filename).is_absolute() and ".." not in Path(item.filename).parts]
        if not safe:
            raise ValueError("Device Browser archive contains no safe CSV file")
        csv_member = max(safe, key=lambda item: item.file_size)
        extracted = archive.read(csv_member)
    if not extracted.strip():
        raise ValueError("Device Browser CSV payload is empty")
    return extracted


def refresh(conn, url: str | None = None, api_key: str | None = None, cache: Path | None = None) -> dict:
    url = url or os.getenv("DEVICEBROWSERINFO_CSV_URL", "").strip()
    api_key = api_key if api_key is not None else os.getenv("DEVICEBROWSERINFO_API_KEY", "")
    if not url: return {"status": "not_configured", "records_upserted": 0}
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    custom = os.getenv("DEVICEBROWSERINFO_AUTH_HEADER", "").strip()
    if custom and api_key: headers[custom] = api_key; headers.pop("Authorization", None)
    parsed = urlparse(url)
    local_path = Path(url) if not parsed.scheme else None
    if local_path and local_path.is_file():
        payload = local_path.read_bytes()
    else:
        with urlopen(Request(url, headers=headers), timeout=60) as response: payload = response.read()
    payload = _csv_payload(payload, url)
    cache = cache or Path(os.getenv("DEVICEBROWSERINFO_CACHE", "data/device_browser_info.csv"))
    rows = csv.DictReader(io.StringIO(payload.decode("utf-8-sig", "replace")))
    now = datetime.now(timezone.utc).isoformat()
    records = {}
    for row in rows:
        network = (row.get("ip") or row.get("network") or row.get("ipAddress") or "").strip()
        if not network:
            continue
        try:
            network = str(ipaddress.ip_network(network, strict=False))
        except ValueError:
            try:
                address = ipaddress.ip_address(network)
                network = str(ipaddress.ip_network(f"{address}/{address.max_prefixlen}", strict=False))
            except ValueError:
                continue
        proxy_type = (row.get("proxyType") or row.get("proxy_type") or "").strip().lower() or None
        is_datacenter = (row.get("isDataCenter") or row.get("is_data_center") or "").strip().lower() == "true"
        if is_datacenter or proxy_type == "data_center":
            proxy_type = "datacenter"
        try:
            score = float(row.get("score") or 0)
        except (TypeError, ValueError):
            score = 0.0
        metadata = {
            "asn": row.get("asn") or row.get("asn.asn"),
            "organization": row.get("organization") or row.get("asn.name"),
            "ip_prefix": row.get("ip_prefix") or row.get("asn.network"),
            "country_code": row.get("country_code") or row.get("geo.countryCode") or row.get("countryCode"),
            "city": row.get("city"),
            "latitude": row.get("latitude"),
            "longitude": row.get("longitude"),
            "is_proxy": row.get("is_proxy") or row.get("isProxy"),
            "is_datacenter": row.get("is_data_center") or row.get("isDataCenter"),
        }
        metadata = {key: value for key, value in metadata.items() if value not in (None, "")}
        records[network] = (
            network, "proxy", None, proxy_type, score, "device_browser",
            row.get("firstSeenAt") or now, row.get("lastSeenAt") or now, now, json.dumps(metadata),
        )
    conn.execute("UPDATE privacy_networks SET active=0 WHERE source='device_browser' AND kind='proxy'")
    values = list(records.values())
    if not values:
        return {"status": "failed", "error": "Device Browser CSV contains no valid IP records", "records_upserted": 0}
    atomic_write(cache, payload)  # replace only after archive/CSV validation
    conn.executemany("""INSERT INTO privacy_networks(network,kind,provider,proxy_type,score,source,first_seen,last_seen,checked_at,metadata_json,active)
          VALUES(?,?,?,?,?,?,?,?,?,?,1) ON CONFLICT(source,kind,network) DO UPDATE SET proxy_type=excluded.proxy_type,score=excluded.score,last_seen=excluded.last_seen,checked_at=excluded.checked_at,metadata_json=excluded.metadata_json,active=1""",
          values)
    conn.executemany("INSERT INTO privacy_network_history(network,kind,provider,proxy_type,score,source,first_seen,last_seen,observed_at,metadata_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
                     [(network, kind, provider, proxy_type, score, source, first_seen, last_seen, now, metadata)
                      for network, kind, provider, proxy_type, score, source, first_seen, last_seen, _checked, metadata in values])
    conn.commit()
    return {"status":"updated", "records_upserted":len(values), "cache":str(cache)}
