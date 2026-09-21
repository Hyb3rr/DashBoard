"""Replay-safe behavioral event to session evidence aggregation."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Iterable

from ..core.traffic_validity import optional_bool


class BehaviorEventIdentityConflict(ValueError):
    """Raised when one event ID carries more than one payload identity."""


_CANONICAL_TIE_FIELDS = (
    "assigned_country", "country_source", "geo_confidence", "geo_conflict",
    "cf_bot_score", "cf_js_detection_passed", "is_tor", "is_vpn", "is_proxy",
    "is_hosting", "is_mobile", "is_scanner",
)


def _payload_identity(event: dict[str, Any]) -> str:
    payload_hash = event.get("payload_hash")
    if payload_hash:
        return str(payload_hash)
    legacy_fields = {
        key: event.get(key)
        for key in ("event_id", "event_time", "visitor_id", "session_id", "event_name", "path", "engagement_ms", "key_event_name")
    }
    return hashlib.sha256(json.dumps(legacy_fields, sort_keys=True, default=str, separators=(",", ":")).encode()).hexdigest()


def _canonical_key(event: dict[str, Any], payload_hash: str) -> tuple[str, str, str, tuple[str, ...]]:
    ingested_at = event.get("ingested_at")
    event_time = event.get("event_time")
    return (
        "" if ingested_at is None else str(ingested_at),
        "" if event_time is None else str(event_time),
        payload_hash,
        tuple("" if event.get(field) is None else str(event.get(field)) for field in _CANONICAL_TIE_FIELDS),
    )


def _canonicalize_events(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    anonymous: list[dict[str, Any]] = []
    for event in events:
        event_id = str(event.get("event_id") or "")
        if event_id:
            grouped[event_id].append(event)
        else:
            anonymous.append(event)

    canonical: list[dict[str, Any]] = list(anonymous)
    for event_id, rows in grouped.items():
        identities = {_payload_identity(row) for row in rows}
        if len(identities) > 1:
            raise BehaviorEventIdentityConflict(
                f"event_id={event_id} has conflicting payload identities: {sorted(identities)}"
            )
        payload_hash = next(iter(identities))
        canonical.append(min(rows, key=lambda row: _canonical_key(row, payload_hash)))
    return canonical


def aggregate_behavior_sessions(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aggregate atomic events by explicit session ID without network inference."""
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in _canonicalize_events(events):
        session_id = str(event.get("session_id") or "")
        if not session_id:
            continue
        groups[session_id].append(event)

    result = []
    for session_id, rows in groups.items():
        ordered = sorted(rows, key=lambda row: (row.get("event_time") or "", str(row.get("event_id") or "")))
        visitors = {str(row.get("visitor_id")) for row in ordered if row.get("visitor_id")}
        pageviews = sum(row.get("event_name") == "page_view" for row in ordered)
        engagements = [float(row["engagement_ms"]) for row in ordered if row.get("event_name") == "engagement" and row.get("engagement_ms") is not None]
        key_events = [str(row.get("key_event_name")) for row in ordered if row.get("event_name") == "key_event" and row.get("key_event_name")]
        countries = {str(row.get("assigned_country")) for row in ordered if row.get("assigned_country")}
        country = sorted(countries)[0] if countries else None
        result.append({
            "session_id": session_id,
            "visitor_id": next(iter(visitors), None) if len(visitors) <= 1 else sorted(visitors)[0],
            "first_event_at": ordered[0].get("event_time"),
            "last_event_at": ordered[-1].get("event_time"),
            "events_count": len(ordered),
            "pageviews": pageviews,
            "engagement_seconds": round(sum(engagements) / 1000.0, 3) if engagements else None,
            "key_event_count": len(key_events),
            "key_event_names": sorted(set(key_events)),
            "pageview_event_count": pageviews,
            "engagement_event_count": len(engagements),
            "has_pageview": bool(pageviews),
            "has_engagement": bool(engagements),
            "has_key_event": bool(key_events),
            "identity_conflict": len(visitors) > 1,
            "assigned_country": country,
            "country_source": next((row.get("country_source") for row in ordered if row.get("country_source")), None),
            "geo_confidence": next((row.get("geo_confidence") for row in ordered if row.get("geo_confidence") is not None), None),
            "geo_conflict": len(countries) > 1 or any(
                optional_bool(row.get("geo_conflict")) is True for row in ordered
            ),
            "network_evidence": {
                "cf_bot_score": next((row.get("cf_bot_score") for row in ordered if row.get("cf_bot_score") is not None), None),
                **{
                    key: next((optional_bool(row.get(key)) for row in ordered if row.get(key) is not None), None)
                    for key in ("cf_js_detection_passed", "is_tor", "is_vpn", "is_proxy", "is_hosting", "is_mobile", "is_scanner")
                },
            },
        })
    return sorted(result, key=lambda row: row["session_id"])


__all__ = ["aggregate_behavior_sessions"]
