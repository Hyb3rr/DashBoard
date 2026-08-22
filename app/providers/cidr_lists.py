"""CIDR feed adapter using PostgreSQL persistence."""
from __future__ import annotations

from pathlib import Path


def refresh_cidr_source(conn, source: str, url: str, kind: str, cache: Path | None = None) -> dict:
    from .pg_intel import refresh_cidr

    return refresh_cidr(conn, source, url, kind, cache=cache)
