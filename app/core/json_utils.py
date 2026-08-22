"""Shared JSON helpers (formerly in app.core.db)."""

from __future__ import annotations

import json


def encode(value) -> str:
    return json.dumps([] if value is None else value, ensure_ascii=False)


def decode(value) -> list | dict:
    try:
        return json.loads(value or "[]")
    except (json.JSONDecodeError, TypeError):
        return []
