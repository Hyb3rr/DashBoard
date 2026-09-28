"""Analyst-owned triage state — pure helper functions, no DB dependency.

Actual persistence is handled by DispositionRepository in app.db.repositories.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json

STATES = {"new", "monitor", "investigate", "escalate", "resolved"}


def _now() -> str:
    """Return the current UTC timestamp as an ISO-formatted string."""
    return datetime.now(timezone.utc).isoformat()


def recommendation(label: str | None) -> str | None:
    """Suggest an analyst triage state for supported risk classifications."""
    return {"critical": "investigate", "medium": "monitor"}.get(label)


def _decode(value):
    """Decode stored JSON and use an empty list when it is malformed."""
    try:
        return json.loads(value or "[]")
    except json.JSONDecodeError:
        return []
