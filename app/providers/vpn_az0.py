"""AZ0 VPN manifest adapter using PostgreSQL persistence."""
from __future__ import annotations


def refresh(conn, url: str | None = None, timeout: int = 30) -> dict:
    from .pg_intel import refresh_az0

    return refresh_az0(conn, url=url, timeout=timeout)
