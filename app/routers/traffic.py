from datetime import datetime, timedelta, timezone
import ipaddress

from fastapi import APIRouter, HTTPException, Query

from ..config import settings
from ..db import clickhouse as clickhouse_store
from ..db import postgres as postgres_store

router = APIRouter()


def _parse_traffic_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    except ValueError:
        return None


def _country_ips(country: str, exclude: bool) -> list[str] | None:
    if exclude:
        return []
    try:
        with postgres_store.transaction() as conn:
            rows = conn.execute("SELECT ip::text AS ip FROM ip_profiles WHERE country_code=%s", (country.upper(),)).fetchall()
        return [str(row["ip"]) for row in rows]
    except Exception as exc:
        raise HTTPException(503, f"PostgreSQL country state unavailable: {exc}") from exc


def _traffic(start, end, bucket, name, label, source, filter_type, filter_value, exclude):
    allowed = _country_ips(str(filter_value), exclude) if filter_type == "country" else None
    try:
        result = clickhouse_store.traffic(start, end, bucket, dataset_id=settings.DATASET_LIVE_ID,
                                          filter_type=filter_type, filter_value=filter_value,
                                          exclude=exclude, allowed_ips=allowed)
    except Exception as exc:
        raise HTTPException(503, f"ClickHouse traffic unavailable: {exc}") from exc
    result.update({"bucket": f"{bucket // 60}min" if bucket < 3600 else f"{bucket // 3600}h",
                   "range": name, "range_label": label, "start": start.isoformat(), "end": end.isoformat(),
                   "filter": {"type": filter_type, "value": filter_value, "exclude": bool(exclude)} if filter_type else None,
                   "source": source, "as_of": datetime.now(timezone.utc).isoformat()})
    return result


@router.get("/api/analytics/traffic")
def traffic_analytics(range_key: str = Query("1h", alias="range"), start: str | None = None, end: str | None = None,
                      filter_type: str | None = None, filter_value: str | None = None, exclude: bool = False,
                      source: str = Query("all", pattern="^(all|stream)$")):
    ranges = {"30m": (1800, 300, "last 30 minutes"), "1h": (3600, 600, "last 1 hour"),
              "6h": (21600, 1800, "last 6 hours"), "12h": (43200, 3600, "last 12 hours"),
              "1d": (86400, 7200, "last 1 day"), "3d": (259200, 21600, "last 3 days"),
              "7d": (604800, 43200, "last 7 days"), "30d": (2592000, 86400, "last 30 days")}
    selected = ranges.get(range_key, ranges["1h"])
    now = datetime.now(timezone.utc)
    end_stamp = _parse_traffic_time(end) if end else now
    start_stamp = _parse_traffic_time(start) if start else end_stamp - timedelta(seconds=selected[0])
    if end_stamp is None or end_stamp > now: end_stamp = now
    if start_stamp is None: start_stamp = end_stamp - timedelta(seconds=selected[0])
    if end_stamp <= start_stamp: raise HTTPException(400, "Invalid traffic time range")
    bucket = selected[1]
    if start: bucket = max(60, min(3600, int((end_stamp - start_stamp).total_seconds()) // 12))
    if filter_type not in {None, "ip", "path", "country"} or (filter_type and not filter_value):
        raise HTTPException(400, "Invalid traffic filter")
    return _traffic(start_stamp, end_stamp, bucket, "custom" if start else range_key,
                    "custom window" if start else selected[2], source, filter_type, filter_value, exclude)


@router.get("/api/ip/{ip}/traffic")
def ip_traffic(ip: str, range_key: str = Query("1h", alias="range"), start: str | None = None, end: str | None = None):
    try: address = str(ipaddress.ip_address(ip))
    except ValueError as exc: raise HTTPException(400, "Invalid IP address") from exc
    seconds = {"30m": 1800, "1h": 3600, "6h": 21600, "12h": 43200, "1d": 86400, "3d": 259200, "7d": 604800}.get(range_key, 3600)
    now = datetime.now(timezone.utc)
    end_stamp = _parse_traffic_time(end) if end else now
    start_stamp = _parse_traffic_time(start) if start else end_stamp - timedelta(seconds=seconds)
    if end_stamp is None or end_stamp > now: end_stamp = now
    if start_stamp is None: start_stamp = end_stamp - timedelta(seconds=seconds)
    if end_stamp <= start_stamp: raise HTTPException(400, "Invalid traffic time range")
    bucket = max(60, min(3600, int((end_stamp - start_stamp).total_seconds()) // 12))
    try: result = clickhouse_store.traffic_for_ip(start_stamp, end_stamp, bucket, address, settings.DATASET_LIVE_ID)
    except Exception as exc: raise HTTPException(503, f"ClickHouse traffic unavailable: {exc}") from exc
    result.update({"ip": address, "range": range_key, "range_label": f"last {range_key}",
                   "start": start_stamp.isoformat(), "end": end_stamp.isoformat(), "as_of": now.isoformat()})
    return result
