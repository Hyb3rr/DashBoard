"""Fail-closed identity boundary for an authenticated reverse proxy."""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable


Network = ipaddress.IPv4Network | ipaddress.IPv6Network
_IDENTITY = re.compile(r"^[A-Za-z0-9._@:+\-]{1,320}$")


def trusted_peer(peer: str | None, networks: Iterable[Network]) -> bool:
    try:
        address = ipaddress.ip_address(str(peer or ""))
    except ValueError:
        return False
    return any(address in network for network in networks)


def valid_proxy_identity(peer: str | None, identity: str | None, networks: Iterable[Network]) -> bool:
    value = str(identity or "").strip()
    return (
        trusted_peer(peer, networks)
        and bool(_IDENTITY.fullmatch(value))
    )
