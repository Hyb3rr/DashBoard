"""Small helpers for canonical IP and network lookups."""

from __future__ import annotations

import ipaddress


def candidate_networks(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> list[str]:
    """Generate canonical host and prefix candidates for indexed containment lookups."""
    return list(dict.fromkeys(
        [str(address)]
        + [
            str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))
            for prefix in range(address.max_prefixlen + 1)
        ]
    ))
