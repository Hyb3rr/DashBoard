"""Shared high-confidence web security path markers."""

from __future__ import annotations

import json
from pathlib import Path


_RULES_PATH = Path(__file__).resolve().parents[2] / "rules" / "early" / "security-markers.json"
SECURITY_MARKERS: tuple[tuple[str, str], ...] = tuple(
    (str(marker), str(rule_id))
    for marker, rule_id in json.loads(_RULES_PATH.read_text(encoding="utf-8"))["markers"]
)


def match_security_marker(path: str | None) -> tuple[str, str] | None:
    """Return (rule_id, marker) for a sensitive request path, if present."""
    normalized = (path or "").split("?", 1)[0].lower()
    for marker, rule_id in SECURITY_MARKERS:
        if marker in normalized:
            return rule_id, marker
    return None
