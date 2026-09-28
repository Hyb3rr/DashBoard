"""Shared JSON helpers (formerly in app.core.db)."""

from __future__ import annotations

import json


def encode(value) -> str:
    """Encode JSON-compatible data, using an empty list for missing values."""
    return json.dumps([] if value is None else value, ensure_ascii=False)


def decode(value) -> list | dict:
    """Decode JSON data and return an empty list when the input is invalid."""
    try:
        return json.loads(value or "[]")
    except (json.JSONDecodeError, TypeError):
        return []
