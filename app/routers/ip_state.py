from datetime import datetime, timedelta, timezone
import ipaddress

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

from ..core.enrichment import _address_scope, abuse_reputation_state, intel_tags_for_abuse
from ..core.intelligence import classify_ip
from ..core.calibration import csv_text
from ..db.repositories import AiRepository, StateRepository

router = APIRouter()

@router.get("/api/ips/calibration.csv", response_class=PlainTextResponse)
def calibration_export():
    """Export current predictions and signals for manual labeling."""
    return PlainTextResponse(
        csv_text(list_ips(limit=5000)),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=ip-calibration.csv"},
    )


@router.get("/api/ips")
def list_ips(limit: int = 100):
    """Return a bounded first page of IP records for legacy dashboard clients."""
    bounded = min(max(limit, 1), 5000)
    result = StateRepository().page(1, bounded, "threat_signal_score", "desc")
    return _pg_rows(result["rows"])


@router.get("/api/ips/page")
def ip_page(
    page: int = 1,
    page_size: int = 50,
    sort: str = "threat_signal_score",
    direction: str = "desc",
    q: str | None = None,
    privacy: str | None = None,
    classification: str | None = None,
    disposition: str | None = None,
):
    """Return one filtered IP inventory page with pagination metadata."""
    page = max(1, int(page))
    page_size = min(50, max(1, int(page_size)))
    intel_tag = privacy if privacy and privacy.startswith("intel:") else None
    privacy = None if intel_tag else privacy
    result = StateRepository().page(page, page_size, sort, direction, q, privacy, classification, disposition, intel_tag)
    return {
        "items": _pg_list_rows(result["rows"]), "page": page, "page_size": page_size,
        "total_items": result["total"], "total_pages": (result["total"] + page_size - 1) // page_size,
        "change_cursor": result["cursor"], "snapshot_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/api/ips/summary")
def ip_summary(start: str | None = None, end: str | None = None):
    """Return an IP summary for a validated UTC time window."""
    now = datetime.now(timezone.utc)
    end_stamp = _parse_summary_time(end) if end else now
    start_stamp = _parse_summary_time(start) if start else end_stamp - timedelta(days=1)
    if end_stamp is None or start_stamp is None or end_stamp > now or end_stamp <= start_stamp:
        raise HTTPException(400, "Invalid summary time range")
    summary = StateRepository().summary_window(start_stamp, end_stamp)
    summary["priority_items"] = _pg_items(summary.pop("priority_ips"), compact=True)
    summary["ai"] = AiRepository().summary()
    summary["snapshot_at"] = datetime.now(timezone.utc).isoformat()
    return summary


def _parse_summary_time(value: str | None) -> datetime | None:
    """Parse a dashboard time parameter into an aware UTC timestamp."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    except ValueError:
        return None


def _apply_geo_fallback(profile: dict) -> dict:
    """Use the canonical profile location, falling back to the geo cache."""
    location = profile.get("network_location")
    if not isinstance(location, dict) or not location:
        country = profile.get("geo_country")
        country_code = profile.get("geo_country_code")
        if country is not None or country_code is not None:
            profile["network_location"] = {
                key: value for key, value in {
                    "country": country,
                    "country_code": country_code,
                    "city": profile.get("geo_city"),
                    "asn": profile.get("geo_asn"),
                    "organization": profile.get("geo_organization"),
                    "network_type": profile.get("geo_network_type"),
                    "confidence": profile.get("geo_confidence"),
                    "disputed": profile.get("geo_disputed"),
                    "scope": profile.get("geo_location_scope"),
                    "sources": ["geo_resolutions"],
                }.items() if value is not None
            }
        else:
            profile["network_location"] = {}
    location = profile["network_location"]
    for field, geo_field in (("country", "geo_country"), ("country_code", "geo_country_code"),
                             ("city", "geo_city"), ("asn", "geo_asn"),
                             ("organization", "geo_organization"), ("network_type", "geo_network_type")):
        if not profile.get(field) and profile.get(geo_field) is not None:
            profile[field] = profile[geo_field]
    return profile


def _disposition_payload(row: dict, *, include_history: bool) -> dict:
    """Project persisted analyst disposition fields into the response DTO."""
    payload = {
        "state": row.get("disposition") or "new",
        "suggested_state": row.get("suggested_state"),
        "assigned_to": row.get("assigned_to"),
        "note": row.get("note"),
        "updated_at": row.get("disposition_updated_at").isoformat() if hasattr(row.get("disposition_updated_at"), "isoformat") else row.get("disposition_updated_at"),
    }
    if include_history:
        payload["history"] = row.get("disposition_history") or []
    return payload


def _compact_network_location(location: dict | None) -> dict | None:
    """Project canonical location metadata into the compact inventory DTO."""
    if not location:
        return None
    compact = {
        key: location.get(key)
        for key in ("country", "country_code", "city", "scope", "location_status")
        if location.get(key) is not None
    }
    canonical = location.get("canonical_resolution") or {}
    if canonical:
        compact["canonical_resolution"] = {
            key: canonical.get(key)
            for key in ("status", "resolved", "candidates")
            if canonical.get(key) is not None
        }
    return compact


def _pipeline_payload(observation: dict, row: dict) -> dict:
    """Build ingestion-to-state timing metadata for an IP response."""
    received_at = observation.get("pipeline_received_at")
    state_ready_at = observation.get("pipeline_state_ready_at")
    profile_ready_at = row.get("updated_at")
    candidates = [value for value in (state_ready_at, profile_ready_at) if value]
    ready_at = max(candidates, key=_as_utc) if candidates else None
    serialized_at = datetime.now(timezone.utc)
    return {
        "received_at": _iso_value(received_at),
        "state_ready_at": _iso_value(state_ready_at),
        "profile_ready_at": _iso_value(profile_ready_at),
        "ready_at": _iso_value(ready_at),
        "api_serialized_at": serialized_at.isoformat(),
        "backend_ready_ms": _elapsed_ms(received_at, ready_at),
    }


def _prepare_profile(row: dict, observation: dict) -> dict:
    """Build a normalized profile with stable defaults for optional evidence."""
    excluded = {"observation_payload", "label", "classification_score", "classification_confidence", "disposition"}
    profile = {key: value for key, value in row.items() if key not in excluded}
    _apply_geo_fallback(profile)
    profile["ip"] = str(row.get("ip") or observation.get("ip") or profile.get("ip"))
    list_fields = {"identity_evidence", "reputation", "provider_errors", "evidence", "sources"}
    mapping_fields = {"provider_status", "field_sources"}
    for key in list_fields | mapping_fields:
        if profile.get(key) is None:
            profile[key] = [] if key in list_fields else {}
    profile["abuse_reputation"] = abuse_reputation_state(
        profile.get("threat_indicators"), profile.get("provider_status")
    )
    profile["intel_tags"] = intel_tags_for_abuse(profile["abuse_reputation"])
    return profile


def _classification_payload(row: dict, profile: dict, observation: dict) -> dict:
    """Apply persisted classification fields over the deterministic assessment."""
    classification = classify_ip(profile, observation, {}, None)
    if row.get("label") is not None:
        classification["label"] = row["label"]
    if row.get("classification_score") is not None:
        classification["score"] = int(row["classification_score"])
    if row.get("classification_confidence") is not None:
        classification["confidence"] = int(row["classification_confidence"])
    return classification


def _dashboard_summary_fields(observation: dict, classification: dict, profile: dict) -> dict:
    """Project compact risk and request counters used by dashboard views."""
    score = int(classification.get("score", 0))
    label = classification.get("label", "unknown")
    return {
        "threat_signal_score": score,
        "threat_signal_label": label,
        "profile_risk_score": int(profile.get("risk_score") or 0),
        "effective_risk_score": score,
        "effective_risk_level": label,
        "requests": int(observation.get("requests") or 0),
        "status_4xx": int(observation.get("status_4xx") or 0),
        "status_5xx": int(observation.get("status_5xx") or 0),
        "unique_paths": int(observation.get("unique_paths") or 0),
        "first_seen": observation.get("first_seen"),
        "last_seen": observation.get("last_seen"),
    }


def _pg_item(row: dict, ai_profile: dict | None = None) -> dict:
    """Build the dashboard contract from the PostgreSQL state read model."""
    observation = dict(row.get("observation_payload") or {})
    observation.setdefault("recent_behavior_score", observation.get("behavior_score", 0))
    observation.setdefault("behavior_evidence", observation.get("recent_behavior_evidence", []))
    profile = _prepare_profile(row, observation)

    # Region context is intentionally excluded from the realtime IP hot path.
    # AI is explanatory/read-only here. Rules and persisted classification state
    # remain the source of classification decisions.
    classification = _classification_payload(row, profile, observation)
    scoring_mode = observation.get("classification_scoring_mode")
    effective_behavior = observation.get("classification_behavior_score")
    if scoring_mode == "family_max" and isinstance(effective_behavior, int) and not isinstance(effective_behavior, bool):
        breakdown = classification.get("score_breakdown")
        if isinstance(breakdown, dict) and "behavior_a" in breakdown:
            classification["score_breakdown"] = {**breakdown, "behavior_a": effective_behavior}
        explanations = classification.get("score_explanations")
        if isinstance(explanations, dict):
            explanations = dict(explanations)
            explanations["A"] = (
                f"A = {effective_behavior}: family-max of the selected recent rule detections."
            )
            classification["score_explanations"] = explanations
    api_observation = {
        key: value for key, value in observation.items()
        if key not in {"classification_scoring_mode", "classification_behavior_score"}
    }
    item = {
        **profile,
        "ip": profile["ip"],
        "observation": api_observation,
        "classification": classification,
        "disposition": _disposition_payload(row, include_history=True),
        "ai_profile": ai_profile or {},
        "ai_status": "ready" if ai_profile else "pending",
        **_dashboard_summary_fields(observation, classification, profile),
    }
    item["pipeline"] = _pipeline_payload(observation, row)
    return item


def _as_utc(value) -> datetime:
    """Normalize supported timestamp values to an aware UTC datetime."""
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _iso_value(value) -> str | None:
    """Serialize a supported timestamp or return null when unavailable."""
    if not value:
        return None
    try:
        return _as_utc(value).isoformat()
    except (TypeError, ValueError):
        return None


def _elapsed_ms(start, end) -> float | None:
    """Calculate a non-negative elapsed duration in milliseconds."""
    if not start or not end:
        return None
    try:
        return round(max(0.0, (_as_utc(end) - _as_utc(start)).total_seconds() * 1000), 2)
    except (TypeError, ValueError):
        return None


def _pg_items(ips: list[str] | set[str], compact: bool = False) -> list[dict]:
    """Load and project a collection of IPs using the selected response shape."""
    return _pg_items_with_mode(ips, compact=compact)


def _pg_items_with_mode(ips: list[str] | set[str], compact: bool = False) -> list[dict]:
    """Join persisted IP rows with AI scores before response projection."""
    repo = StateRepository()
    rows = repo.get_many(ips)
    scores = {str(item["ip"]): item for item in AiRepository().scores(ips)}
    return [_pg_compact_item(row, scores.get(str(row["ip"]))) if compact else _pg_item(row, scores.get(str(row["ip"]))) for row in rows]


def _pg_rows(rows: list[dict]) -> list[dict]:
    """Project full investigation response objects for database rows."""
    ips = [str(row["ip"]) for row in rows]
    scores = {str(item["ip"]): item for item in AiRepository().scores(ips)}
    return [_pg_item(row, scores.get(str(row["ip"]))) for row in rows]


def _pg_compact_item(row: dict, ai_profile: dict | None = None) -> dict:
    """Build the bounded list/realtime DTO; investigation detail stays full-fat."""
    source_observation = dict(row.get("observation_payload") or {})
    profile = dict(row)
    _apply_geo_fallback(profile)
    observation = {
        key: source_observation.get(key)
        for key in (
            "requests", "status_4xx", "status_5xx", "unique_paths",
            "first_seen", "last_seen", "pipeline_received_at",
            "pipeline_state_ready_at",
        )
        if source_observation.get(key) is not None
    }
    label = row.get("label") or "unknown"
    score = int(row.get("classification_score") or 0)
    confidence = int(row.get("classification_confidence") or 0)
    provider_status = row.get("provider_status") or {}
    reputation = abuse_reputation_state(row.get("threat_indicators"), provider_status)
    source_location = profile.get("network_location")
    location = source_location if isinstance(source_location, dict) else None
    ip_text = str(row.get("ip") or "")
    address = ipaddress.ip_address(ip_text)
    item = {
        "ip": ip_text,
        "address_scope": _address_scope(address),
        "is_non_public": not address.is_global,
        "country": profile.get("country"), "country_code": profile.get("country_code"),
        "city": profile.get("city"), "region": profile.get("region"),
        "network_location": _compact_network_location(location),
        "network_type": profile.get("network_type"),
        "organization": profile.get("organization"), "asn": profile.get("asn"),
        "is_tor": row.get("is_tor"), "is_vpn": row.get("is_vpn"),
        "is_proxy": row.get("is_proxy"), "is_hosting": row.get("is_hosting"),
        "intel_tags": intel_tags_for_abuse(reputation),
        "observation": observation,
        "classification": {"label": label, "score": score, "confidence": confidence},
        "threat_signal_score": score, "threat_signal_label": label,
        "disposition": _disposition_payload(row, include_history=False),
        "requests": int(observation.get("requests") or 0),
        "status_4xx": int(observation.get("status_4xx") or 0),
        "status_5xx": int(observation.get("status_5xx") or 0),
        "unique_paths": int(observation.get("unique_paths") or 0),
        "first_seen": observation.get("first_seen"), "last_seen": observation.get("last_seen"),
        "ai_profile": ai_profile or {}, "ai_status": "ready" if ai_profile else "pending",
    }
    return item


def _pg_list_rows(rows: list[dict]) -> list[dict]:
    """Project compact inventory DTOs with their associated AI summaries."""
    ips = [str(row["ip"]) for row in rows]
    scores = {str(item["ip"]): item for item in AiRepository().scores(ips)}
    return [_pg_compact_item(row, scores.get(str(row["ip"]))) for row in rows]


@router.get("/api/ips/snapshot")
def ip_snapshot(limit: int = 500):
    """Return the current bounded IP inventory and change cursor."""
    bounded = min(max(limit, 1), 500)
    result = StateRepository().page(1, bounded, "threat_signal_score", "desc")
    return {"items": _pg_rows(result["rows"]), "cursor": result["cursor"], "snapshot_at": datetime.now(timezone.utc).isoformat()}


@router.get("/api/ips/updates")
def ip_updates(after: int = 0, limit: int = 500):
    """Return compact changed-IP rows after a durable sequence cursor."""
    limit = min(max(limit, 1), 500)
    result = StateRepository().changes(after, limit)
    if result.get("reset_required"):
        return {"items": [], "cursor": result["current"], "has_more": False, "reset_required": True, "transitions": []}
    rows = result["rows"]
    items = _pg_items({str(row["ip"]) for row in rows}, compact=True)
    return {
        "items": items,
        "transitions": [row for row in rows if row["reason"] == "classification"],
        "cursor": int(rows[-1]["seq"]) if result.get("has_more") and rows else result["current"],
        "has_more": bool(result.get("has_more")), "reset_required": False,
    }
