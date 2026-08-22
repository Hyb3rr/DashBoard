"""Small helpers for canonical IP and network lookups."""

from __future__ import annotations

import ipaddress


def candidate_networks(address: ipaddress._BaseAddress) -> list[str]:
    """Return every canonical network that can contain ``address``.

    PostgreSQL intelligence tables store canonical CIDR strings. Querying
    these candidates lets the database use its network index instead of
    scanning every stored prefix, while the caller performs a final
    containment check for defensive validation.
    """
    return list(dict.fromkeys(
        [str(address)]
        + [
            str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))
            for prefix in range(address.max_prefixlen + 1)
        ]
    ))
