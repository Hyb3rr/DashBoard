"""Cloudflare anycast ranges: hosting/CDN signal, never VPN signal."""
from __future__ import annotations

from pathlib import Path


def refresh(conn, url: str | None = None, cache: Path | None = None) -> dict:
    """Refresh Cloudflare network ranges as hosting context, not VPN evidence."""
    from .pg_intel import refresh_cloudflare

    return refresh_cloudflare(conn, url=url, cache=cache)
