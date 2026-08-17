"""Small helpers for canonical IP and network lookups."""

from __future__ import annotations

import ipaddress


def candidate_networks(address: ipaddress._BaseAddress) -> list[str]:
    """Return every canonical network that can contain ``address``.

    Local intelligence tables store canonical CIDR strings.  Querying these
    candidates lets SQLite use the network index instead of scanning every
    stored prefix, while the caller can still perform a final containment
    check for defensive validation.
    """
    return list(dict.fromkeys(
        [str(address)]
        + [
            str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))
            for prefix in range(address.max_prefixlen + 1)
        ]
    ))
