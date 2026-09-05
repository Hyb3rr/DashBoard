"""Pure policy for selecting semantic change-feed events for AI explanation."""

from __future__ import annotations

from dataclasses import dataclass

from .case_packets import build_trigger_identity


TRIGGER_CONSUMER = "foundation_sec_auto_trigger"
MEANINGFUL_TRANSITIONS = frozenset({
    ("good", "critical"),
    ("unknown", "medium"),
    ("unknown", "critical"),
    ("low", "medium"),
    ("low", "critical"),
    ("medium", "critical"),
})


@dataclass(frozen=True)
class TriggerEvent:
    seq: int
    ip: str
    reason: str
    old_label: str | None = None
    new_label: str | None = None


def is_meaningful_trigger(event: TriggerEvent) -> bool:
    if event.reason == "rare_path_evidence_updated":
        return True
    if event.reason != "classification":
        return False
    transition = ((event.old_label or "unknown").lower(), (event.new_label or "").lower())
    return transition in MEANINGFUL_TRANSITIONS


__all__ = ["MEANINGFUL_TRANSITIONS", "TRIGGER_CONSUMER", "TriggerEvent", "build_trigger_identity", "is_meaningful_trigger"]
