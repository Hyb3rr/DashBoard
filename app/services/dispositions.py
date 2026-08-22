"""Analyst-owned triage state — pure helper functions, no DB dependency.

Actual persistence is handled by DispositionRepository in app.db.repositories.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json

STATES = {"new", "monitor", "investigate", "escalate", "resolved"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def recommendation(label: str | None) -> str | None:
    return {"bad": "investigate", "watch": "monitor"}.get(label)


def _decode(value):
    try:
        return json.loads(value or "[]")
    except json.JSONDecodeError:
        return []
