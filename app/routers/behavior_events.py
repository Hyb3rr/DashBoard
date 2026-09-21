"""Bounded, validation-only behavioral event intake."""

from __future__ import annotations

import json
import time
from collections import deque
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ..core.behavior_events import MAX_BATCH_SIZE, MAX_EVENT_BYTES, normalize_behavior_event
from ..core.trusted_network import get_trusted_network_context
from ..db import clickhouse

router = APIRouter()
_rate_windows: dict[str, deque[float]] = {}
_RATE_LIMIT = 120
_RATE_WINDOW_SECONDS = 60.0
_RATE_CLEANUP_INTERVAL_SECONDS = 30.0
_last_rate_cleanup = 0.0


def _rate_limited(key: str, now: float) -> bool:
    global _last_rate_cleanup
    if now - _last_rate_cleanup >= _RATE_CLEANUP_INTERVAL_SECONDS:
        for client_key, timestamps in list(_rate_windows.items()):
            while timestamps and now - timestamps[0] >= _RATE_WINDOW_SECONDS:
                timestamps.popleft()
            if not timestamps:
                _rate_windows.pop(client_key, None)
        _last_rate_cleanup = now
    window = _rate_windows.setdefault(key, deque())
    while window and now - window[0] >= _RATE_WINDOW_SECONDS:
        window.popleft()
    if len(window) >= _RATE_LIMIT:
        return True
    window.append(now)
    return False


@router.post("/api/behavior/events")
async def receive_behavior_events(request: Request) -> JSONResponse:
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        return JSONResponse({"accepted": 0, "rejected": 0, "error": "content_type_required"}, status_code=415)
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_EVENT_BYTES:
        return JSONResponse({"accepted": 0, "rejected": 0, "error": "payload_too_large"}, status_code=413)
    client_key = request.client.host if request.client else "unknown"
    if _rate_limited(client_key, time.monotonic()):
        return JSONResponse({"accepted": 0, "rejected": 0, "error": "rate_limited"}, status_code=429)
    raw = await request.body()
    if len(raw) > MAX_EVENT_BYTES:
        return JSONResponse({"accepted": 0, "rejected": 0, "error": "payload_too_large"}, status_code=413)
    try:
        payload: Any = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return JSONResponse({"accepted": 0, "rejected": 0, "error": "malformed_json"}, status_code=400)
    events = payload.get("events") if isinstance(payload, dict) and "events" in payload else [payload]
    if not isinstance(events, list) or not events:
        return JSONResponse({"accepted": 0, "rejected": 0, "error": "events_required"}, status_code=400)
    if len(events) > MAX_BATCH_SIZE:
        return JSONResponse({"accepted": 0, "rejected": len(events), "error": "batch_too_large"}, status_code=413)
    normalized = []
    errors = []
    for index, event in enumerate(events):
        try:
            item = normalize_behavior_event(event)
            item.update(get_trusted_network_context(request))
            normalized.append(item)
        except (TypeError, ValueError) as exc:
            errors.append({"index": index, "code": "INVALID_EVENT", "reason": str(exc)[:120]})
    if not normalized:
        return JSONResponse({"accepted": 0, "duplicates": 0, "conflicts": 0, "rejected": len(errors), "errors": errors})
    try:
        result = clickhouse.insert_behavior_events(normalized)
    except Exception:
        return JSONResponse({"accepted": 0, "duplicates": 0, "conflicts": 0, "rejected": len(events), "errors": [{"code": "STORAGE_UNAVAILABLE"}]}, status_code=503)
    result["rejected"] += len(errors)
    result["errors"] = errors + result.get("errors", [])
    return JSONResponse(result)
