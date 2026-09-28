"""Fail-closed parsing of security context from a trusted ingress only."""

from __future__ import annotations

import ipaddress
from typing import Any

from fastapi import Request

from ..config import settings


_BOOLEAN_HEADERS = {
    "x-is-tor": "is_tor",
    "x-is-vpn": "is_vpn",
    "x-is-proxy": "is_proxy",
    "x-is-hosting": "is_hosting",
}
_TRUE_VALUES = {"1", "true", "yes", "passed"}
_FALSE_VALUES = {"0", "false", "no", "failed"}


def _trusted_peer(request: Request) -> bool:
    """Verify the immediate request peer belongs to a configured trusted proxy."""
    if not settings.TRUST_PROXY_HEADERS or not settings.TRUSTED_PROXY_NETWORKS:
        return False
    peer = request.client.host if request.client else None
    try:
        address = ipaddress.ip_address(peer or "")
    except ValueError:
        return False
    return any(address in network for network in settings.TRUSTED_PROXY_NETWORKS)


def _optional_bool(value: str | None) -> bool | None:
    """Parse recognized proxy boolean headers while preserving unknown values."""
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    return None


def get_trusted_network_context(request: Request) -> dict[str, Any]:
    """Return provider headers only when the immediate peer is trusted."""
    if not _trusted_peer(request):
        return {}
    headers = request.headers
    country = headers.get("cf-ipcountry")
    bot_score = headers.get("cf-bot-score")
    js_passed = headers.get("cf-bot-management-js-detection-passed")
    try:
        bot = int(bot_score) if bot_score is not None else None
        bot = bot if bot is not None and 0 <= bot <= 99 else None
    except ValueError:
        bot = None
    valid_country = country.upper() if country and len(country) == 2 and country.isalpha() else None
    return {
        "assigned_country": valid_country,
        "country_source": "cloudflare_header" if valid_country else None,
        "geo_confidence": 1.0 if valid_country else None,
        "geo_conflict": None,
        "cf_bot_score": bot,
        "cf_js_detection_passed": _optional_bool(js_passed),
        **{field: _optional_bool(headers.get(header)) for header, field in _BOOLEAN_HEADERS.items()},
    }


__all__ = ["get_trusted_network_context"]
