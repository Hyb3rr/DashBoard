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


def automatic_transition(
    current_state: str | None,
    classification_label: str | None,
    alert_reason_type: str | None = None,
) -> tuple[str, str] | None:
    """Return a safe automatic disposition transition and its audit reason."""
    state = (current_state or "new").lower()
    label = (classification_label or "unknown").lower()
    if state == "new" and label == "medium":
        return "monitor", "medium_classification"
    if state == "new" and label == "critical":
        return "investigate", "critical_classification"
    if state == "monitor" and label == "critical":
        return "investigate", "critical_classification"
    if state == "monitor" and label == "medium":
        if alert_reason_type == "monitored_recurrence":
            return "investigate", "monitored_recurrence"
        if alert_reason_type == "classification_transition":
            return "investigate", "medium_classification"
    return None


def _decode(value):
    """Decode stored JSON and use an empty list when it is malformed."""
    try:
        return json.loads(value or "[]")
    except json.JSONDecodeError:
        return []
