from datetime import datetime, timezone

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

from ..core.intelligence import classify_ip
from ..tools.calibration import csv_text
from ..db.repositories import StateRepository

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
    bounded = min(max(limit, 1), 5000)
    result = StateRepository().page(1, bounded, "threat_signal_score", "desc")
    return [_pg_item(row) for row in result["rows"]]


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
    page = max(1, int(page))
    page_size = min(50, max(1, int(page_size)))
    result = StateRepository().page(page, page_size, sort, direction, q, privacy, classification, disposition)
    return {
        "items": [_pg_item(row) for row in result["rows"]], "page": page, "page_size": page_size,
        "total_items": result["total"], "total_pages": (result["total"] + page_size - 1) // page_size,
        "change_cursor": result["cursor"], "snapshot_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/api/ips/summary")
def ip_summary():
    summary = StateRepository().summary()
    summary["priority_items"] = _pg_items(summary.pop("priority_ips"))
    summary["ai"] = {"scored": 0, "flagged": 0, "coverage": 0}
    summary["snapshot_at"] = datetime.now(timezone.utc).isoformat()
    return summary


def _pg_item(row: dict) -> dict:
    """Build the dashboard contract from the PostgreSQL state read model."""
    observation = dict(row.get("observation_payload") or {})
    observation.setdefault("recent_behavior_score", observation.get("behavior_score", 0))
    observation.setdefault("behavior_evidence", observation.get("recent_behavior_evidence", []))
    profile = {key: value for key, value in row.items() if key not in {"observation_payload", "label", "classification_score", "classification_confidence", "disposition"}}
    profile["ip"] = str(row.get("ip") or observation.get("ip") or profile.get("ip"))
    for key in ("identity_evidence", "reputation", "provider_errors", "provider_status", "field_sources", "evidence", "sources"):
        if profile.get(key) is None:
            profile[key] = [] if key in {"identity_evidence", "reputation", "provider_errors", "evidence", "sources"} else {}
    
    # Region context is intentionally excluded from the realtime IP hot path.
    classification = classify_ip(profile, observation, {}, None)
    if row.get("label"):
        classification["label"] = row["label"]
        classification["score"] = int(row.get("classification_score") or classification["score"])
        classification["confidence"] = int(row.get("classification_confidence") or classification.get("confidence", 0))
    
    item = {
        **profile,
        "ip": profile["ip"],
        "observation": observation,
        "classification": classification,
        "threat_signal_score": int(classification.get("score", 0)),
        "threat_signal_label": classification.get("label", "unknown"),
        "disposition": {
            "state": row.get("disposition") or "new",
            "suggested_state": row.get("suggested_state"),
            "assigned_to": row.get("assigned_to"),
            "note": row.get("note"),
            "updated_at": row.get("disposition_updated_at").isoformat() if hasattr(row.get("disposition_updated_at"), "isoformat") else row.get("disposition_updated_at"),
            "history": row.get("disposition_history") or [],
        },
        "profile_risk_score": int(profile.get("risk_score") or 0),

        "effective_risk_score": int(classification.get("score", 0)),
        "effective_risk_level": classification.get("label", "unknown"),
        "requests": int(observation.get("requests") or 0),
        "status_4xx": int(observation.get("status_4xx") or 0),
        "status_5xx": int(observation.get("status_5xx") or 0),
        "unique_paths": int(observation.get("unique_paths") or 0),
        "first_seen": observation.get("first_seen"),
        "last_seen": observation.get("last_seen"),
    }
    received_at = observation.get("pipeline_received_at")
    state_ready_at = observation.get("pipeline_state_ready_at")
    profile_ready_at = row.get("updated_at")
    ready_candidates = [value for value in (state_ready_at, profile_ready_at) if value]
    ready_at = max(ready_candidates, key=lambda value: _as_utc(value)) if ready_candidates else None
    serialized_at = datetime.now(timezone.utc)
    item["pipeline"] = {
        "received_at": _iso_value(received_at),
        "state_ready_at": _iso_value(state_ready_at),
        "profile_ready_at": _iso_value(profile_ready_at),
        "ready_at": _iso_value(ready_at),
        "api_serialized_at": serialized_at.isoformat(),
        "backend_ready_ms": _elapsed_ms(received_at, ready_at),
    }
    return item


def _as_utc(value) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _iso_value(value) -> str | None:
    if not value:
        return None
    try:
        return _as_utc(value).isoformat()
    except (TypeError, ValueError):
        return None


def _elapsed_ms(start, end) -> float | None:
    if not start or not end:
        return None
    try:
        return round(max(0.0, (_as_utc(end) - _as_utc(start)).total_seconds() * 1000), 2)
    except (TypeError, ValueError):
        return None


def _pg_items(ips: list[str] | set[str]) -> list[dict]:
    repo = StateRepository()
    return [_pg_item(row) for row in repo.get_many(ips)]


@router.get("/api/ips/snapshot")
def ip_snapshot(limit: int = 500):
    bounded = min(max(limit, 1), 500)
    result = StateRepository().page(1, bounded, "threat_signal_score", "desc")
    return {"items": [_pg_item(row) for row in result["rows"]], "cursor": result["cursor"], "snapshot_at": datetime.now(timezone.utc).isoformat()}


@router.get("/api/ips/updates")
def ip_updates(after: int = 0, limit: int = 500):
    limit = min(max(limit, 1), 500)
    result = StateRepository().changes(after, limit)
    if result.get("reset_required"):
        return {"items": [], "cursor": result["current"], "has_more": False, "reset_required": True, "transitions": []}
    rows = result["rows"]
    items = _pg_items({str(row["ip"]) for row in rows})
    return {
        "items": items,
        "transitions": [row for row in rows if row["reason"] == "classification"],
        "cursor": int(rows[-1]["seq"]) if result.get("has_more") and rows else result["current"],
        "has_more": bool(result.get("has_more")), "reset_required": False,
    }
