from __future__ import annotations

import ipaddress
import json
import os
import socket
from datetime import datetime, timezone
from urllib.request import Request, urlopen


def _values(item, key):
    value = item.get(key) if isinstance(item, dict) else None
    if isinstance(value, str): return [value]
    if isinstance(value, list): return value
    return []


def _addresses(value: str, resolve=True) -> list[str]:
    try:
        return [str(ipaddress.ip_address(value))]
    except ValueError:
        if not resolve: return []
        try:
            return list(dict.fromkeys(str(item[4][0]) for item in socket.getaddrinfo(value, None, type=socket.SOCK_STREAM)))
        except OSError:
            return []


def refresh(conn, url: str | None = None, timeout: int = 30) -> dict:
    url = url or os.getenv("AZ0_VPN_MANIFEST_URL", "https://raw.githubusercontent.com/az0/vpn_ip/main/data/get_addresses_via_api.json")
    with urlopen(Request(url), timeout=timeout) as response:
        manifest = json.loads(response.read().decode("utf-8"))
    providers = manifest.get("providers", manifest) if isinstance(manifest, dict) else manifest
    if not isinstance(providers, dict): providers = {str(i): value for i, value in enumerate(providers or [])}
    now = datetime.now(timezone.utc).isoformat(); total = 0; statuses = {}
    conn.execute("UPDATE privacy_networks SET active=0 WHERE source='az0_vpn_ip' AND kind='vpn'")
    for name, item in providers.items():
        if not isinstance(item, dict): statuses[name] = {"status": "failed"}; continue
        found=[]; errors=[]
        urls = _values(item, "urls") or _values(item, "url")
        for mirror in urls:
            try:
                with urlopen(Request(mirror), timeout=timeout) as response: data=json.loads(response.read().decode("utf-8"))
                for ip in _values(data, item.get("ip_key", "")): found += _addresses(ip, False)
                for host in _values(data, item.get("hostname_key", "")): found += _addresses(host, True)
                if found: break
            except Exception as exc: errors.append(f"{type(exc).__name__}: {exc}")
        found=list(dict.fromkeys(found))
        for network in found:
            conn.execute("""INSERT INTO privacy_networks(network,kind,provider,source,first_seen,last_seen,checked_at,metadata_json,active)
              VALUES(?,?,?,?,?,?,?,?,1) ON CONFLICT(source,kind,network) DO UPDATE SET provider=excluded.provider,last_seen=excluded.last_seen,checked_at=excluded.checked_at,active=1""",
              (network,"vpn",name,"az0_vpn_ip",now,now,now,json.dumps({"errors":errors})))
            conn.execute("INSERT INTO privacy_network_history(network,kind,provider,source,first_seen,last_seen,observed_at,metadata_json) VALUES(?,?,?,?,?,?,?,?)",
                         (network, "vpn", name, "az0_vpn_ip", now, now, now, json.dumps({"errors": errors})))
        total += len(found); statuses[name] = {"status": "ok" if found and not errors else "partial" if found else "failed", "records": len(found), "errors": errors}
    conn.commit()
    return {"status": "updated" if total else "failed", "records_upserted": total, "providers": statuses}
