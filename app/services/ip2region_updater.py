"""Atomic ip2region xdb updater with format validation."""
from __future__ import annotations

import ipaddress
import os
import tempfile
from pathlib import Path
from urllib.request import Request, urlopen

from .ip2region_reader import ROOT

BASE = "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/"


def refresh():
    import ip2region.util as util
    ROOT.mkdir(parents=True, exist_ok=True)
    updated, errors = [], []
    for name, version in (("ip2region_v4.xdb", util.IPv4), ("ip2region_v6.xdb", util.IPv6)):
        target = ROOT / name
        try:
            with urlopen(Request(BASE + name, headers={"User-Agent": "ip-intelligence/ip2region"}), timeout=60) as response:
                payload = response.read()
            with tempfile.NamedTemporaryFile(dir=ROOT, prefix=f".{name}.", delete=False) as tmp:
                tmp.write(payload)
                temporary = Path(tmp.name)
            util.verify_from_file(str(temporary))
            temporary.replace(target)
            updated.append(name)
        except Exception as exc:
            errors.append(f"{name}: {type(exc).__name__}: {exc}")
            if 'temporary' in locals() and temporary.exists(): temporary.unlink()
    return {"status": "ok" if not errors else "partial" if updated else "failed", "updated": updated, "errors": errors}
