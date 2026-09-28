"""Fail-closed identity boundary for an authenticated reverse proxy."""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable


Network = ipaddress.IPv4Network | ipaddress.IPv6Network
_IDENTITY = re.compile(r"^[A-Za-z0-9._@:+\-]{1,320}$")


def trusted_peer(peer: str | None, networks: Iterable[Network]) -> bool:
    """Check whether a reverse-proxy peer address belongs to an allowlisted network."""
    try:
        address = ipaddress.ip_address(str(peer or ""))
    except ValueError:
        return False
    return any(address in network for network in networks)


def valid_proxy_identity(peer: str | None, identity: str | None, networks: Iterable[Network]) -> bool:
    """Accept an identity header only when it is valid and sent by a trusted peer."""
    value = str(identity or "").strip()
    return (
        trusted_peer(peer, networks)
        and bool(_IDENTITY.fullmatch(value))
    )
