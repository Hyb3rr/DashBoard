from datetime import datetime, timedelta, timezone
import ipaddress

from fastapi import APIRouter, HTTPException, Query

from ..config import settings
from ..db import clickhouse as clickhouse_store


router = APIRouter()


@router.get("/api/raw-logs/tail")
def raw_logs_tail(
    window: int = Query(300, ge=10, le=3600),
    limit: int = Query(100, ge=1, le=500),
    ip: str | None = None,
    status: int | None = Query(None, ge=100, le=599),
):
    now = datetime.now(timezone.utc)
    parsed_ip = None
    if ip:
        try:
            parsed_ip = str(ipaddress.ip_address(ip))
        except ValueError as exc:
            raise HTTPException(400, "invalid IP filter") from exc
    try:
        events = clickhouse_store.raw_log_tail(
            now - timedelta(seconds=window), now, limit=limit,
            dataset_id=settings.DATASET_LIVE_ID, ip=parsed_ip, status=status,
        )
    except Exception as exc:
        raise HTTPException(503, f"Raw log tail unavailable: {exc}") from exc
    return {"events": events, "window_seconds": window, "limit": limit, "as_of": now.isoformat()}
