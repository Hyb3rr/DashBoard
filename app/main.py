from contextlib import asynccontextmanager

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse, Response
from fastapi.staticfiles import StaticFiles
import asyncio
import ipaddress
import json
import os
import time
import threading
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from .config import settings
from .config.settings import APP_DIR
from .core.logs import effective_risk
from .core.intelligence import classify_ip
from .tools.calibration import csv_text
from .services.profiles import (
    classification_observation,
    ensure_profile_postgres,
)
from .services.dispositions import STATES
from .services.classification_watcher import run_classification_watcher
from .services.coverage import run_coverage_consumer
from .core.rules import ruleset_hash, ruleset_health
from .collectors.websocket_collector import bus, collector
from .core.intel_updater import run_due_sources
from .db import clickhouse as clickhouse_store
from .db import postgres as postgres_store
from .db.repositories import StateRepository, DispositionRepository, RegionRepository


@asynccontextmanager
async def lifespan(_app: FastAPI):
    postgres_store.ensure_schema()
    clickhouse_store.ensure_schema()
    await collector.start()
    watcher = asyncio.create_task(run_classification_watcher())
    coverage = asyncio.create_task(run_coverage_consumer())
    if os.getenv("INTEL_AUTO_UPDATE_ON_STARTUP", "false").strip().lower() in {"1", "true", "yes", "on"}:
        # Remote provider downloads have no reliable cancellation point. Keep
        # this best-effort job outside the server's asyncio default executor so
        # graceful shutdown never waits indefinitely on a remote socket.
        threading.Thread(target=run_due_sources, name="intel-startup-update", daemon=True).start()
    try:
        yield
    finally:
        watcher.cancel()
        coverage.cancel()
        await asyncio.gather(watcher, coverage, return_exceptions=True)
        try:
            await collector.stop()
        finally:
            postgres_store.close_pool()


app = FastAPI(title="Remote Web Monitoring Hub - IP Intelligence", lifespan=lifespan)


@app.middleware("http")
async def timing_middleware(request, call_next):
    started = time.perf_counter()
    response = await call_next(request)
    response.headers["X-Process-Time-ms"] = f"{(time.perf_counter() - started) * 1000:.1f}"
    return response


app.mount("/static", StaticFiles(directory=APP_DIR / "static"), name="static")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000", "null"],
    allow_origin_regex=r"^(null|https?://(localhost|127\.0\.0\.1)(:\d+)?)$",
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return HTMLResponse((APP_DIR / "dashboard.html").read_text())


@app.get("/favicon.ico")
def favicon():
    return Response(status_code=204)


@app.get("/ip/{ip}", response_class=HTMLResponse)
def ip_case_page(ip: str):
    """Serve a stable full-page investigation view for one IP address."""
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise HTTPException(400, "Invalid IP address") from exc
    html = (APP_DIR / "ip_detail.html").read_text()
    return HTMLResponse(html)


@app.get("/regions", response_class=HTMLResponse)
def region_profiles_page():
    return HTMLResponse((APP_DIR / "regions.html").read_text())


@app.get("/regions/{country_code}", response_class=HTMLResponse)
def region_profile_page(country_code: str):
    """Serve the shell even for unknown codes so the page degrades cleanly."""
    return HTMLResponse((APP_DIR / "region_detail.html").read_text())


@app.get("/health")
def health():
    rules_health = ruleset_health()
    collector_info = collector.status() if collector else {"status": "disabled"}
    storage = {
        "backend": settings.DATA_BACKEND,
        "postgres": postgres_store.health(),
        "clickhouse": clickhouse_store.health()
    }
    healthy = rules_health["status"] == "ok" and all(
        item.get("status") == "ok" for item in storage.values() if isinstance(item, dict) and "status" in item
    )
    return {
        "status": "ok" if healthy else "degraded",
        "mode": settings.DATA_BACKEND,
        "rules": rules_health,
        "storage": storage,
        "collector": collector_info,
    }



def _split_allowed_country_ips(country_code: str, exclude: bool = False) -> list[str]:
    if exclude:
        return []
    try:
        with postgres_store.transaction() as conn:
            rows = conn.execute(
                "SELECT ip::text AS ip FROM ip_profiles WHERE country_code = %s",
                (country_code.upper(),),
            ).fetchall()
        return [str(row["ip"]) for row in rows]
    except Exception as exc:
        raise HTTPException(503, f"PostgreSQL country state unavailable: {exc}") from exc


def _traffic_from_split(
    start_stamp: datetime,
    end_stamp: datetime,
    bucket_seconds: int,
    range_name: str,
    range_label: str,
    source: str,
    filter_type: str | None,
    filter_value: str | None,
    exclude: bool,
) -> dict:
    if source == "file":
        dataset_id = "file"
    else:
        dataset_id = settings.DATASET_LIVE_ID
    allowed_ips = None
    if filter_type == "country":
        allowed_ips = _split_allowed_country_ips(str(filter_value), exclude)
    try:
        result = clickhouse_store.traffic(
            start_stamp,
            end_stamp,
            bucket_seconds,
            dataset_id=dataset_id,
            filter_type=filter_type,
            filter_value=filter_value,
            exclude=exclude,
            allowed_ips=allowed_ips,
        )
    except Exception as exc:
        raise HTTPException(503, f"ClickHouse traffic unavailable: {exc}") from exc
    now = datetime.now(timezone.utc)
    result.update({
        "bucket": f"{bucket_seconds // 60}min" if bucket_seconds < 3600 else f"{bucket_seconds // 3600}h",
        "range": range_name,
        "range_label": range_label,
        "start": start_stamp.isoformat(),
        "end": end_stamp.isoformat(),
        "filter": {"type": filter_type, "value": filter_value, "exclude": bool(exclude)} if filter_type else None,
        "source": source,
        "as_of": now.isoformat(),
    })
    return result


@app.get("/api/analytics/traffic")
def traffic_analytics(
    range_key: str = Query("1h", alias="range"),
    start: str | None = None,
    end: str | None = None,
    filter_type: str | None = None,
    filter_value: str | None = None,
    exclude: bool = False,
    source: str = Query("all", pattern="^(all|stream|file)$"),
    mode: str = Query("live", pattern="^(live|file)$"),
):
    """Aggregate one traffic event set for the Overview time window."""
    if not isinstance(mode, str):
        mode = "live"
    if not isinstance(source, str):
        source = "all"
    ranges = {
        "30m": (30 * 60, 5 * 60, "last 30 minutes"),
        "1h": (60 * 60, 10 * 60, "last 1 hour"),
        "6h": (6 * 60 * 60, 30 * 60, "last 6 hours"),
        "12h": (12 * 60 * 60, 60 * 60, "last 12 hours"),
        "1d": (24 * 60 * 60, 2 * 60 * 60, "last 24 hours"),
        "3d": (3 * 24 * 60 * 60, 6 * 60 * 60, "last 3 days"),
        "7d": (7 * 24 * 60 * 60, 12 * 60 * 60, "last 7 days"),
        "30d": (30 * 24 * 60 * 60, 24 * 60 * 60, "last 30 days"),
    }
    selected = ranges.get(range_key, ranges["1h"])
    now = datetime.now(timezone.utc)
    end_stamp = _parse_traffic_time(end) if end else now
    start_stamp = _parse_traffic_time(start) if start else end_stamp - timedelta(seconds=selected[0])
    if end_stamp is None or end_stamp > now:
        end_stamp = now
    if start_stamp is None:
        start_stamp = end_stamp - timedelta(seconds=selected[0])
    if start_stamp is None or end_stamp <= start_stamp:
        raise HTTPException(400, "Invalid traffic time range")
    bucket_seconds = selected[1]
    range_label = "custom window" if start else selected[2]
    range_name = "custom" if start else range_key
    window_seconds = max(60, int((end_stamp - start_stamp).total_seconds()))
    if start:
        bucket_seconds = max(60, min(3600, window_seconds // 12))
    if filter_type not in {None, "ip", "path", "country"} or (filter_type and not filter_value):
        raise HTTPException(400, "Invalid traffic filter")
    return _traffic_from_split(
        start_stamp,
        end_stamp,
        bucket_seconds,
        range_name,
        range_label,
        source,
        filter_type,
        filter_value,
        exclude,
    )


@app.get("/api/ip/{ip}/traffic")
def ip_traffic(ip: str, range_key: str = Query("1h", alias="range"), start: str | None = None, end: str | None = None, mode: str = Query("live", pattern="^(live|file)$")):
    """Return one IP's traffic view from ClickHouse."""
    try:
        address = str(ipaddress.ip_address(ip))
    except ValueError as exc:
        raise HTTPException(400, "Invalid IP address") from exc
    ranges = {"30m": 1800, "1h": 3600, "6h": 21600, "12h": 43200, "1d": 86400, "3d": 259200, "7d": 604800}
    seconds = ranges.get(range_key, ranges["1h"])
    now = datetime.now(timezone.utc)
    end_stamp = _parse_traffic_time(end) if end else now
    start_stamp = _parse_traffic_time(start) if start else end_stamp - timedelta(seconds=seconds)
    if end_stamp is None or end_stamp > now:
        end_stamp = now
    if start_stamp is None:
        start_stamp = end_stamp - timedelta(seconds=seconds)
    if not start_stamp or not end_stamp or end_stamp <= start_stamp:
        raise HTTPException(400, "Invalid traffic time range")
    seconds = max(60, int((end_stamp - start_stamp).total_seconds()))
    bucket_seconds = max(60, min(3600, seconds // 12))
    try:
        result = clickhouse_store.traffic_for_ip(
            start_stamp, end_stamp, bucket_seconds, address, settings.DATASET_LIVE_ID
        )
    except Exception as exc:
        raise HTTPException(503, f"ClickHouse traffic unavailable: {exc}") from exc
    result.update({
        "ip": address, "range": range_key, "range_label": f"last {range_key}",
        "start": start_stamp.isoformat(), "end": end_stamp.isoformat(),
        "as_of": now.isoformat(),
    })
    return result


def _parse_traffic_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


@app.get("/api/ip/{ip}/paths")
def ip_path_activity(ip: str, limit: int = 12, mode: str = Query("live", pattern="^(live|file)$")):
    raise HTTPException(410, "Path Activity endpoint is retired in split live mode; use IP Traffic")


@app.get("/api/ip/{ip}")
async def ip_details(ip: str, refresh: bool = False, mode: str = Query("live", pattern="^(live|file)$")):
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


@app.get("/api/ip/{ip}/attack")
def ip_attack(ip: str, window: str = Query("24h"), mode: str = Query("live", pattern="^(live|file)$")):
    """Return recent observed detections and their explicit techniques."""
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


@app.post("/api/ip/{ip}/disposition")
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


@app.get("/api/regions/demand-signal")
def region_demand_signal(limit: int = 50):
    """Aggregate observed, likely-legitimate traffic by country from PostgreSQL."""
    limit = min(max(limit, 1), 200)
    return RegionRepository().demand_signal(limit)


@app.get("/api/regions/{country_code}")
def region_details(country_code: str):
    data = RegionRepository().get(country_code.upper())
    if not data:
        raise HTTPException(404, "Region profile not found")
    return data


@app.get("/api/ips/calibration.csv", response_class=PlainTextResponse)
def calibration_export():
    """Export current predictions and signals for manual labeling."""
    return PlainTextResponse(
        csv_text(list_ips(limit=5000)),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=ip-calibration.csv"},
    )


@app.get("/api/regions")
def region_list(limit: int = 50):
    limit = min(max(limit, 1), 200)
    return RegionRepository().list(limit=limit)


@app.get("/api/ips")
def list_ips(limit: int = 100, mode: str = Query("live", pattern="^(live|file)$")):
    bounded = min(max(limit, 1), 5000)
    result = StateRepository().page(1, bounded, "threat_signal_score", "desc")
    return [_pg_item(row) for row in result["rows"]]


@app.get("/api/ips/page")
def ip_page(
    page: int = 1,
    page_size: int = 50,
    sort: str = "threat_signal_score",
    direction: str = "desc",
    q: str | None = None,
    privacy: str | None = None,
    classification: str | None = None,
    disposition: str | None = None,
    mode: str = Query("live", pattern="^(live|file)$"),
):
    page = max(1, int(page))
    page_size = min(50, max(1, int(page_size)))
    result = StateRepository().page(page, page_size, sort, direction, q, privacy, classification, disposition)
    return {
        "items": [_pg_item(row) for row in result["rows"]], "page": page, "page_size": page_size,
        "total_items": result["total"], "total_pages": (result["total"] + page_size - 1) // page_size,
        "change_cursor": result["cursor"], "snapshot_at": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/ips/summary")
def ip_summary(mode: str = Query("live", pattern="^(live|file)$")):
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


@app.get("/api/ips/snapshot")
def ip_snapshot(limit: int = 500, mode: str = Query("live", pattern="^(live|file)$")):
    bounded = min(max(limit, 1), 500)
    result = StateRepository().page(1, bounded, "threat_signal_score", "desc")
    return {"items": [_pg_item(row) for row in result["rows"]], "cursor": result["cursor"], "snapshot_at": datetime.now(timezone.utc).isoformat()}


@app.get("/api/ips/updates")
def ip_updates(after: int = 0, limit: int = 500, mode: str = Query("live", pattern="^(live|file)$")):
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


@app.get("/api/collector/status")
def collector_status():
    payload = collector.status()
    payload["ai_state_backend"] = "postgresql_live_only"
    return payload


@app.post("/api/ips/refresh-unknown")
async def refresh_unknown(limit: int = 500, mode: str = Query("live", pattern="^(live|file)$")):
    limit = min(max(limit, 1), 5000)
    with postgres_store.transaction() as pg_conn:
        rows = pg_conn.execute("""SELECT host(o.ip) AS ip
            FROM ip_observations_state o LEFT JOIN ip_profiles p ON p.ip=o.ip
            WHERE p.ip IS NULL OR p.enrichment_status IS DISTINCT FROM 'complete'
               OR p.country IS NULL OR p.country_code IS NULL
            ORDER BY COALESCE(NULLIF(o.payload->>'requests','')::bigint,0) DESC, o.ip ASC
            LIMIT %s""", (limit,)).fetchall()
    selected = [str(row["ip"]) for row in rows]

    async def generate_split():
        yield json.dumps({"type": "start", "selected": len(selected), "mode": "live", "order": "requests_desc"}) + "\n"
        processed = complete = partial = failed = 0
        for ip in selected:
            data, error = await ensure_profile_postgres(ip, refresh=True)
            processed += 1
            if data and not error:
                complete += 1
                status = "complete"
            elif data:
                partial += 1
                status = "partial"
            else:
                failed += 1
                status = "failed"
            yield json.dumps({"type": "item", "ip": ip, "status": status, "error": error}) + "\n"
        yield json.dumps({"type": "done", "selected": len(selected), "processed": processed, "complete": complete, "partial": partial, "failed": failed}) + "\n"

    return StreamingResponse(generate_split(), media_type="application/x-ndjson", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/stream")
async def realtime_stream():
    async def generate():
        iterator = bus.subscribe().__aiter__()
        try:
            while True:
                try:
                    event, payload = await asyncio.wait_for(iterator.__anext__(), timeout=15)
                    yield f"event: {event}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
        except (asyncio.CancelledError, StopAsyncIteration):
            return
        finally:
            await iterator.aclose()

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
