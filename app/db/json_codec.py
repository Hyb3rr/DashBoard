"""Shared JSON adapters for PostgreSQL JSONB values and stable fingerprints."""

from __future__ import annotations

import json
from typing import Any

from psycopg.types.json import Jsonb


def jsonb_value(value: Any) -> Jsonb:
    """Adapt Python values or JSON strings for PostgreSQL JSONB parameters."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            pass
    return Jsonb(value)


def decode_json(value: Any) -> Any:
    """Decode JSON strings returned by drivers while preserving plain text."""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def json_bytes(value: Any) -> bytes:
    """Serialize values deterministically for fingerprints and deduplication."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
