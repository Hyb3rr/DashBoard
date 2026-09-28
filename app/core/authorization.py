"""Small server-side role policy for the trusted reverse-proxy boundary."""

from __future__ import annotations

from collections.abc import Iterable


ROLES = frozenset({"viewer", "analyst", "admin"})
ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}


def parse_roles(value: str | None) -> frozenset[str]:
    """Parse a role header and discard values outside the supported role set."""
    roles = {item.strip().lower() for item in str(value or "").replace(",", " ").split()}
    return frozenset(role for role in roles if role in ROLES)


def has_role(roles: Iterable[str], required: str) -> bool:
    """Check whether the highest assigned role meets a required role level."""
    highest = max((ROLE_RANK.get(str(role).lower(), 0) for role in roles), default=0)
    return highest >= ROLE_RANK[required]


def required_role(method: str, path: str) -> str | None:
    """Map a mutation route to its minimum role, leaving read routes open."""
    if method.upper() in {"GET", "HEAD", "OPTIONS"}:
        return None
    if method.upper() == "PATCH" and path == "/api/alerts/settings":
        return "admin"
    if method.upper() == "PATCH" and path.startswith("/api/alerts/"):
        return "analyst"
    if method.upper() == "POST" and path.endswith("/disposition"):
        return "analyst"
    if method.upper() == "POST" and path == "/api/ai/cases/":
        return "analyst"
    if method.upper() == "POST" and path.startswith("/api/ai/cases/") and path.endswith("/explain"):
        return "analyst"
    if method.upper() == "POST" and path == "/api/ips/refresh-unknown":
        return "admin"
    if method.upper() == "POST" and path == "/api/behavior/events":
        return "viewer"
    return None
