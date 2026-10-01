from datetime import datetime, timedelta, timezone
import ipaddress
import re

from fastapi import APIRouter, HTTPException, Query

from ..config import settings
from ..db import clickhouse as clickhouse_store


router = APIRouter()


@router.get("/api/raw-logs/ip-suggestions")
def raw_log_ip_suggestions(
    prefix: str = Query(..., min_length=2, max_length=45),
    window: int = Query(3600, ge=10, le=86400),
    status: int | None = Query(None, ge=100, le=599),
    limit: int = Query(12, ge=1, le=12),
):
    """Suggest distinct IPs seen in the selected bounded history window."""
    prefix = prefix.strip()
    if len(prefix) < 2 or not re.fullmatch(r"[0-9A-Fa-f:.]+", prefix):
        raise HTTPException(400, "IP prefix may contain only digits, dots, and colons")
    end = datetime.now(timezone.utc)
    start = end - timedelta(seconds=window)
    try:
        ips = clickhouse_store.raw_log_ip_suggestions(
            start, end, prefix, limit=limit, dataset_id=settings.DATASET_LIVE_ID,
            status=status,
        )
    except Exception as exc:
        raise HTTPException(503, f"Raw log IP suggestions unavailable: {exc}") from exc
    return {"ips": ips, "window_seconds": window, "limit": limit}


@router.get("/api/raw-logs/tail")
def raw_logs_tail(
    window: int = Query(3600, ge=10, le=86400),
    limit: int = Query(100, ge=1, le=200),
    ip: str | None = None,
    status: int | None = Query(None, ge=100, le=599),
    as_of: datetime | None = None,
    before_time: datetime | None = None,
    before_event_id: str | None = Query(None, max_length=64),
):
    """Return a bounded raw-log page with optional filters and older cursor."""
    if (before_time is None) != (before_event_id is None):
        raise HTTPException(400, "before_time and before_event_id must be provided together")
    end = as_of or datetime.now(timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    start = end - timedelta(seconds=window)
    parsed_ip = None
    if ip:
        try:
            parsed_ip = str(ipaddress.ip_address(ip))
        except ValueError as exc:
            raise HTTPException(400, "invalid IP filter") from exc
    try:
        events = clickhouse_store.raw_log_tail(
            start, end, limit=limit + 1, dataset_id=settings.DATASET_LIVE_ID,
            ip=parsed_ip, status=status, before_time=before_time,
            before_event_id=before_event_id,
        )
    except Exception as exc:
        raise HTTPException(503, f"Raw log tail unavailable: {exc}") from exc
    has_more = len(events) > limit
    page = events[-limit:]
    next_cursor = None
    if has_more and page:
        next_cursor = {
            "before_time": page[0]["timestamp"],
            "before_event_id": page[0]["event_id"],
        }
    return {
        "events": page,
        "window_seconds": window,
        "limit": limit,
        "as_of": end.isoformat(),
        "has_more": has_more,
        "next_cursor": next_cursor,
    }
