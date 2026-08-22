"""ip2region xdb validation/context reader."""
from __future__ import annotations

import ipaddress
import os
from pathlib import Path

ROOT = Path(os.getenv("IP2REGION_DATA_DIR", "data/ip2region"))
_searchers = {}


def lookup(ip: str) -> dict:
    address = ipaddress.ip_address(ip)
    import ip2region.searcher as xdb
    import ip2region.util as util
    version = util.IPv6 if address.version == 6 else util.IPv4
    path = ROOT / ("ip2region_v6.xdb" if address.version == 6 else "ip2region_v4.xdb")
    if not path.is_file():
        return {"region": None, "source": "ip2region"}
    key = (version, str(path), path.stat().st_mtime_ns)
    searcher = _searchers.get(key)
    if not searcher:
        searcher = xdb.new_with_file_only(version, str(path))
        _searchers[key] = searcher
    region = searcher.search(str(address)) or ""
    parts = (region.split("|") + [None] * 5)[:5]
    return {"region": parts[1], "city": parts[2], "isp": parts[3], "country": parts[0],
            "country_code": parts[4], "source": "ip2region"}
