import asyncio
import ipaddress

from fastapi import APIRouter, Body, HTTPException, Query

from ..services.dispositions import STATES
from ..services.profiles import ensure_profile_postgres
from ..db import postgres as postgres_store
from ..db.repositories import DispositionRepository, StateRepository
from .ip_state import _pg_item

router = APIRouter()


@router.get("/api/ip/{ip}/paths")
def ip_path_activity(ip: str, limit: int = 12):
    raise HTTPException(410, "Path Activity endpoint is retired in split live mode; use IP Traffic")


@router.get("/api/ip/{ip}")
async def ip_details(ip: str, refresh: bool = False):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise HTTPException(400, "Invalid IP address") from exc
    error = None
    if refresh:
        data, error = await ensure_profile_postgres(str(address), refresh=True)
    row = await asyncio.to_thread(StateRepository().get, str(address))
    if not row:
        raise HTTPException(404, "IP not found")
    cached_location = row.get("network_location") or {}
    if not refresh and not cached_location.get("ip2region"):
        _, refresh_error = await ensure_profile_postgres(str(address), refresh=True)
        if not refresh_error:
            row = await asyncio.to_thread(StateRepository().get, str(address))
        else:
            error = refresh_error
    item = _pg_item(row)
    if refresh and error:
        item.setdefault("provider_errors", []).append(f"Refresh failed; showing cached profile: {error}")
    return item


@router.get("/api/ip/{ip}/attack")
def ip_attack(ip: str, window: str = Query("24h")):
    try:
        address = str(ipaddress.ip_address(ip))
    except ValueError as exc:
        raise HTTPException(400, "Invalid IP address") from exc
    if window not in {"1h", "24h"}:
        raise HTTPException(400, "Unsupported attack window")
    row = StateRepository().get(address)
    payload = dict((row or {}).get("observation_payload") or {})
    suffix = "1h" if window == "1h" else "24h"
    detections = payload.get(f"detections_{suffix}", []) or []
    by_technique: dict[str, dict] = {}
    for detection in detections:
        technique = detection.get("mitre_technique")
        if technique:
            item = by_technique.setdefault(technique, {"id": technique, "detection_ids": []})
            if detection.get("id") not in item["detection_ids"]:
                item["detection_ids"].append(detection.get("id"))
    return {
        "ip": address, "window": window,
        "ruleset_hash": payload.get(f"ruleset_hash_{suffix}"),
        "evaluated_at": payload.get(f"evaluated_at_{suffix}"),
        "detections": detections, "techniques": list(by_technique.values()),
    }


@router.post("/api/ip/{ip}/disposition")
def update_ip_disposition(ip: str, payload: dict = Body(...)):
    try:
        address = str(ipaddress.ip_address(ip))
    except ValueError as exc:
        raise HTTPException(400, "Invalid IP address") from exc
    state = str(payload.get("state") or "").lower()
    if state not in STATES:
        raise HTTPException(400, "Invalid disposition state")
    current = StateRepository().get(address)
    label = current.get("label") if current else None
    return DispositionRepository().set(
        address, state, payload.get("assigned_to"), payload.get("note"),
        payload.get("actor") or "system", label,
    )
