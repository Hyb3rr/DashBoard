"""FireHOL feed definitions and PostgreSQL refresh entry point."""
from __future__ import annotations

from pathlib import Path

DEFAULT_LISTS = {
    "firehol_proxies": "proxy", "firehol_anonymous": "anonymous", "dm_tor": "tor", "et_tor": "tor",
    "firehol_webserver": "webserver", "abuseipdb_1d": "abuse", "abuseipdb_30d": "abuse",
    "dshield": "scanner", "feodo": "malware", "dronebl_auto_botnets": "botnet",
    "sslbl": "malware", "zeus": "malware", "palevo": "malware",
}
NETSET_LISTS = {
    "firehol_proxies", "firehol_anonymous", "firehol_webserver", "dshield", "dshield_1d",
    "dshield_30d", "dshield_7d", "dronebl_auto_botnets",
}
FIREHOL_SOURCES = {
    name: {"url": f"https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/{name}{'.netset' if name in NETSET_LISTS else '.ipset'}",
           "enabled": name not in {"sslbl", "zeus", "palevo"}}
    for name in DEFAULT_LISTS
}


def list_url(name: str) -> str:
    return FIREHOL_SOURCES.get(name, {}).get("url") or f"https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/{name}{'.netset' if name in NETSET_LISTS else '.ipset'}"


def refresh_list(conn, name: str, category: str | None = None, url: str | None = None, cache_dir: Path | None = None) -> dict:
    from .pg_intel import refresh_firehol

    return refresh_firehol(conn, name, category=category, url=url, cache_dir=cache_dir)
