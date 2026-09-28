"""Contract validation for first-party behavioral events.

Behavior events are distinct from HTTP request telemetry. Identity is explicit;
the contract never derives it from IP address, user-agent, or timing.
"""

from __future__ import annotations

from datetime import datetime
from datetime import timezone
import hashlib
import json
from typing import Any


EVENT_NAMES = frozenset({"page_view", "engagement", "key_event"})
KEY_EVENT_NAMES = frozenset({"signup", "contact_submit", "checkout_start", "purchase", "download"})
ALLOWED_FIELDS = frozenset({"event_id", "timestamp", "visitor_id", "session_id", "event_name", "path", "engagement_ms", "key_event_name"})
SERVER_CONTEXT_FIELDS = ("assigned_country", "country_source", "geo_confidence", "geo_conflict", "cf_bot_score", "cf_js_detection_passed", "is_tor", "is_vpn", "is_proxy", "is_hosting", "is_mobile", "is_scanner")
MAX_EVENT_BYTES = 16_384
MAX_BATCH_SIZE = 25
MAX_ID_LENGTH = 128
MAX_PATH_LENGTH = 2_048
MAX_KEY_EVENT_LENGTH = 64
MAX_ENGAGEMENT_MS = 86_400_000


def _validated_identity(event: dict[str, Any]) -> tuple[str, str, str, str, str]:
    """Validate required identity and event fields in their established order."""
    event_id = str(event.get("event_id") or "").strip()
    visitor_id = str(event.get("visitor_id") or "").strip()
    session_id = str(event.get("session_id") or "").strip()
    event_name = str(event.get("event_name") or "").strip()
    timestamp = str(event.get("timestamp") or "").strip()
    if not event_id or len(event_id) > MAX_ID_LENGTH:
        raise ValueError("event_id is required")
    if not visitor_id or not session_id or len(visitor_id) > MAX_ID_LENGTH or len(session_id) > MAX_ID_LENGTH:
        raise ValueError("visitor_id and session_id are required; identity is never inferred")
    if event_name not in EVENT_NAMES:
        raise ValueError("unsupported behavior event_name")
    if not timestamp:
        raise ValueError("timestamp is required")
    return event_id, visitor_id, session_id, event_name, timestamp


def _validate_timestamp(timestamp: str) -> None:
    """Enforce ISO-8601 timezone and event-retention bounds."""
    try:
        parsed_timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be ISO-8601") from exc
    if parsed_timestamp.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    age_seconds = (datetime.now(timezone.utc) - parsed_timestamp.astimezone(timezone.utc)).total_seconds()
    if age_seconds < -300:
        raise ValueError("timestamp is too far in the future")
    if age_seconds > 90 * 86400:
        raise ValueError("timestamp is outside retention window")


def _normalize_engagement(value: Any) -> float | None:
    """Validate engagement duration and normalize numeric values to float."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0 or value > MAX_ENGAGEMENT_MS:
        raise ValueError("engagement_ms must be a non-negative number or null")
    return float(value)


def _normalize_key_event(event_name: str, value: Any) -> str | None:
    """Validate event-specific key-event names and normalize accepted values."""
    if event_name == "key_event" and not str(value or "").strip():
        raise ValueError("key_event_name is required for key_event")
    if event_name != "key_event" and value is not None:
        raise ValueError("key_event_name is only valid for key_event")
    if event_name == "key_event" and (len(str(value)) > MAX_KEY_EVENT_LENGTH or str(value).strip() not in KEY_EVENT_NAMES):
        raise ValueError("unsupported key_event_name")
    return str(value).strip() if value is not None else None


def normalize_behavior_event(event: dict[str, Any]) -> dict[str, Any]:
    """Validate and return the small append-only event payload."""
    if not isinstance(event, dict):
        raise ValueError("behavior event must be an object")
    if set(event) - ALLOWED_FIELDS:
        raise ValueError("unsupported event fields")
    event_id, visitor_id, session_id, event_name, timestamp = _validated_identity(event)
    _validate_timestamp(timestamp)
    engagement_ms = _normalize_engagement(event.get("engagement_ms"))
    path = str(event.get("path") or "")
    if len(path) > MAX_PATH_LENGTH:
        raise ValueError("path is too long")
    key_event_name = _normalize_key_event(event_name, event.get("key_event_name"))
    normalized = {
        "event_id": event_id,
        "timestamp": timestamp,
        "visitor_id": visitor_id,
        "session_id": session_id,
        "event_name": event_name,
        "path": path,
        "engagement_ms": engagement_ms,
        "key_event_name": str(key_event_name).strip() if key_event_name is not None else None,
    }
    normalized["payload_hash"] = hashlib.sha256(json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return normalized


__all__ = ["EVENT_NAMES", "normalize_behavior_event"]
