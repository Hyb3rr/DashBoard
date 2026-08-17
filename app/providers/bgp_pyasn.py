"""Local pyasn snapshot access.

Building a pyasn database from RouteViews/RIPE RIS MRT files is an offline
operation. Runtime lookups never contact the network; deployment replaces the
configured snapshot atomically.
"""
from __future__ import annotations

import os
from pathlib import Path


def lookup(ip: str, snapshot: str | Path | None = None) -> dict:
    path = Path(snapshot or os.getenv("GEO_PYASN_DB_PATH", "data/geo/pyasn.dat"))
    if not path.is_file():
        return {}
    try:
        import pyasn

        asn_db = pyasn.pyasn(str(path))
        asn, prefix = asn_db.lookup(ip)
        return {"asn": f"AS{asn}" if asn else None, "ip_prefix": prefix, "source": "pyasn"}
    except (ImportError, OSError, ValueError):
        return {}
