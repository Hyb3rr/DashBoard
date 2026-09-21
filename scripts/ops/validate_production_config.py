#!/usr/bin/env python3
"""Fail-closed preflight for a production Sentinel Hub process."""

from __future__ import annotations

import ipaddress
import os
import sys


VALID_ROLES = {"all", "api", "collector", "worker", "ai"}


def validate_environment(env: dict[str, str] | None = None) -> list[str]:
    values = env if env is not None else os.environ
    errors: list[str] = []

    role = values.get("APP_ROLE", "all").strip().lower() or "all"
    if role not in VALID_ROLES:
        errors.append("APP_ROLE must be one of: all, api, collector, worker, ai")

    if not values.get("POSTGRES_DSN", "").strip():
        errors.append("POSTGRES_DSN is required")
    if not values.get("CLICKHOUSE_HOST", "").strip():
        errors.append("CLICKHOUSE_HOST is required")

    auth_required = values.get("AUTH_REQUIRED", "false").strip().lower() in {"1", "true", "yes", "on"}
    if not auth_required:
        errors.append("AUTH_REQUIRED must be true for an exposed deployment")
    proxy_cidrs = [item.strip() for item in values.get("AUTH_TRUSTED_PROXY_CIDRS", "").split(",") if item.strip()]
    for cidr in proxy_cidrs:
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            errors.append(f"AUTH_TRUSTED_PROXY_CIDRS contains invalid network: {cidr}")
    if auth_required and not proxy_cidrs:
        errors.append("AUTH_TRUSTED_PROXY_CIDRS is required when AUTH_REQUIRED is true")

    security_headers = values.get("SECURITY_HEADERS_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
    if not security_headers:
        errors.append("SECURITY_HEADERS_ENABLED must be true for an exposed deployment")

    hosts = [item.strip() for item in values.get("TRUSTED_HOSTS", "").split(",") if item.strip()]
    if not hosts:
        errors.append("TRUSTED_HOSTS must contain at least one explicit host")
    if "*" in hosts:
        errors.append("TRUSTED_HOSTS must not contain wildcard '*'")

    if role in {"all", "collector"} and values.get("LOG_WS_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}:
        for key in ("LOG_WS_URL", "LOG_WS_TOKEN", "LOG_WS_SOURCE_ID"):
            if not values.get(key, "").strip():
                errors.append(f"{key} is required when LOG_WS_ENABLED is true")
    return errors


def main() -> int:
    from dotenv import load_dotenv

    load_dotenv()
    errors = validate_environment()
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("production config: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
