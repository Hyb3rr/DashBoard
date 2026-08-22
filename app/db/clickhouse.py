from __future__ import annotations

import os
from datetime import datetime, timezone
import ipaddress
from typing import Any, Iterable
from ..core import metrics
from ..core.path_canonicalization import canonicalize_path


def configured() -> bool:
    return bool(os.getenv("CLICKHOUSE_HOST"))


def connect():
    try:
        import clickhouse_connect
    except ImportError as exc:  # pragma: no cover - optional deployment extra
        raise RuntimeError("clickhouse-connect is required for DATA_BACKEND=split") from exc
    return clickhouse_connect.get_client(
        host=os.getenv("CLICKHOUSE_HOST", "127.0.0.1"),
        port=int(os.getenv("CLICKHOUSE_PORT", "8123")),
        username=os.getenv("CLICKHOUSE_USER", "default"),
        password=os.getenv("CLICKHOUSE_PASSWORD", ""),
        database=os.getenv("CLICKHOUSE_DATABASE", "ipintel"),
        secure=os.getenv("CLICKHOUSE_SECURE", "false").lower() in {"1", "true", "yes"},
    )


def health() -> dict[str, Any]:
    client = None
    try:
        client = connect()
        client.query("SELECT 1")
        return {"status": "ok"}
    except Exception as exc:
        return {"status": "failed", "error": f"{type(exc).__name__}: {exc}"[:240]}
    finally:
        if client is not None:
            client.close()


def ensure_schema() -> None:
    """Create ClickHouse storage once during application startup, never in health checks."""
    client = connect()
    try:
        client.command("""
            CREATE TABLE IF NOT EXISTS http_events (
              event_time DateTime64(3, 'UTC'), ingested_at DateTime64(3, 'UTC'),
              dataset_id LowCardinality(String), source_id LowCardinality(String),
              source_offset UInt64, event_id FixedString(64), src_ip IPv6,
              method LowCardinality(String), path String, status UInt16,
              bytes_sent UInt64, referer String, user_agent String, raw_line String
            ) ENGINE = ReplacingMergeTree(ingested_at)
            PARTITION BY toYYYYMM(event_time)
            ORDER BY (dataset_id, event_id, event_time, src_ip, source_id, source_offset)
        """)
    finally:
        client.close()


def insert_events(rows: Iterable[dict[str, Any]]) -> int:
    payload = list(rows)
    if not payload:
        return 0
    finish = metrics.timed("clickhouse.insert_batch_ms")
    client = connect()
    try:
        columns = [
            "event_time", "ingested_at", "dataset_id", "source_id", "source_offset",
            "event_id", "src_ip", "method", "path", "status", "bytes_sent",
            "referer", "user_agent", "raw_line",
        ]
        values = []
        for row in payload:
            values.append([
                row.get("timestamp"),
                row.get("ingested_at"),
                row.get("dataset_id", "live"),
                row.get("source_id", ""),
                int(row.get("source_offset") or 0),
                row.get("event_id", ""),
                row.get("src_ip", ""),
                row.get("method", ""),
                row.get("path", ""),
                int(row.get("status") or 0),
                int(row.get("bytes_sent") or 0),
                row.get("referer") or "",
                row.get("user_agent") or "",
                row.get("raw_line", ""),
            ])
        client.insert("http_events", values, column_names=columns)
        metrics.increment("collector.events_ingested", len(payload))
        metrics.increment("clickhouse.insert_batches")
        return len(payload)
    except Exception:
        metrics.increment("clickhouse.insert_errors")
        raise
    finally:
        finish()
        client.close()


def _rows(result) -> list[dict[str, Any]]:
    return [dict(zip(result.column_names, row)) for row in result.result_rows]


def _display_ip(value: Any) -> str:
    address = ipaddress.ip_address(str(value))
    return str(address.ipv4_mapped or address)


def _iso_utc(value: Any) -> str:
    """Serialize ClickHouse DateTime values with an explicit UTC offset."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return str(value)


def traffic(
    start: datetime,
    end: datetime,
    bucket_seconds: int,
    dataset_id: str = "live",
    filter_type: str | None = None,
    filter_value: str | None = None,
    exclude: bool = False,
    allowed_ips: list[str] | None = None,
) -> dict[str, Any]:
    """Aggregate the traffic overview inside ClickHouse.

    Only aggregate result rows cross the application boundary; raw events
    stay in ClickHouse.  `allowed_ips` is supplied by PostgreSQL for the
    country filter because network identity state belongs to the state plane.
    """
    client = connect()
    try:
        conditions = [
            "event_time >= {start:DateTime64(3)}",
            "event_time <= {end:DateTime64(3)}",
            "dataset_id = {dataset_id:String}",
        ]
        params: dict[str, Any] = {
            "start": start.astimezone(timezone.utc),
            "end": end.astimezone(timezone.utc),
            "dataset_id": dataset_id,
        }
        if filter_type == "ip":
            conditions.append("src_ip != {filter_value:IPv6}" if exclude else "src_ip = {filter_value:IPv6}")
            params["filter_value"] = filter_value
        elif filter_type == "path":
            conditions.append("path != {filter_value:String}" if exclude else "path = {filter_value:String}")
            params["filter_value"] = filter_value
        elif filter_type == "country":
            ips = allowed_ips or []
            if exclude:
                conditions.append("src_ip NOT IN {allowed_ips:Array(IPv6)}")
            else:
                conditions.append("src_ip IN {allowed_ips:Array(IPv6)}")
            params["allowed_ips"] = ips
        where = " AND ".join(conditions)
        base = f"FROM http_events FINAL WHERE {where}"
        series_result = client.query(
            f"SELECT toStartOfInterval(event_time, INTERVAL {int(bucket_seconds)} SECOND) AS timestamp, count() AS requests, countIf(status >= 400) AS errors {base} GROUP BY timestamp ORDER BY timestamp",
            parameters=params,
        )
        status_result = client.query(
            f"SELECT countIf(status BETWEEN 200 AND 299) AS s2, countIf(status BETWEEN 300 AND 399) AS s3, countIf(status BETWEEN 400 AND 499) AS s4, countIf(status >= 500) AS s5, count() AS total, uniqExact(src_ip) AS unique_ip_count {base}",
            parameters=params,
        )
        path_result = client.query(
            f"SELECT path, count() AS requests {base} GROUP BY path ORDER BY requests DESC, path ASC LIMIT 8",
            parameters=params,
        )
        ip_result = client.query(
            f"SELECT src_ip, count() AS requests {base} GROUP BY src_ip ORDER BY requests DESC, src_ip ASC LIMIT 8",
            parameters=params,
        )
        country_ip_result = client.query(
            f"SELECT src_ip, count() AS requests {base} GROUP BY src_ip",
            parameters=params,
        )
        series = [
            {"timestamp": _iso_utc(row["timestamp"]), "requests": int(row["requests"]), "errors": int(row["errors"])}
            for row in _rows(series_result)
        ]
        status = _rows(status_result)[0] if _rows(status_result) else {"s2": 0, "s3": 0, "s4": 0, "s5": 0, "total": 0, "unique_ip_count": 0}
        top_paths = [{"path": row["path"], "requests": int(row["requests"]), "ips": []} for row in _rows(path_result)]
        top_ips = [{"ip": _display_ip(row["src_ip"]), "requests": int(row["requests"])} for row in _rows(ip_result)]
        country_rows = [{"ip": _display_ip(row["src_ip"]), "requests": int(row["requests"])} for row in _rows(country_ip_result)]
        from .postgres import countries_for_ips
        profiles = countries_for_ips([row["ip"] for row in country_rows])
        country_totals: dict[tuple[str, str], int] = {}
        for row in country_rows:
            profile = profiles.get(row["ip"], {})
            key = (profile.get("country_code") or "", profile.get("country") or "Unknown")
            country_totals[key] = country_totals.get(key, 0) + row["requests"]
        top_countries = [
            {"country_code": code, "country": country, "requests": requests, "ips": []}
            for (code, country), requests in sorted(country_totals.items(), key=lambda item: (-item[1], item[0]))[:8]
        ]
        return {
            "series": series,
            "status_codes": {"2xx": int(status["s2"]), "3xx": int(status["s3"]), "4xx": int(status["s4"]), "5xx": int(status["s5"])},
            "top_paths": top_paths,
            "top_ips": top_ips,
            "top_countries": top_countries,
            "total_requests": int(status["total"]),
            "error_requests": int(status["s4"] + status["s5"]),
            "unique_ips": int(status.get("unique_ip_count") or 0),
            "unique_countries": len(country_totals),
        }
    finally:
        client.close()


def traffic_for_ip(start: datetime, end: datetime, bucket_seconds: int, ip: str, dataset_id: str = "live") -> dict[str, Any]:
    """Return the IP-detail traffic view without leaving ClickHouse."""
    client = connect()
    try:
        params = {"start": start.astimezone(timezone.utc), "end": end.astimezone(timezone.utc), "ip": ip, "dataset_id": dataset_id}
        base = "FROM http_events FINAL WHERE event_time >= {start:DateTime64(3)} AND event_time <= {end:DateTime64(3)} AND src_ip = {ip:IPv6} AND dataset_id = {dataset_id:String}"
        series = _rows(client.query(f"SELECT toStartOfInterval(event_time, INTERVAL {int(bucket_seconds)} SECOND) AS timestamp, count() AS requests, countIf(status >= 400) AS errors {base} GROUP BY timestamp ORDER BY timestamp", parameters=params))
        status = _rows(client.query(f"SELECT countIf(status BETWEEN 200 AND 299) AS s2,countIf(status BETWEEN 300 AND 399) AS s3,countIf(status BETWEEN 400 AND 499) AS s4,countIf(status >= 500) AS s5,count() AS total {base}", parameters=params))
        paths = _rows(client.query(f"SELECT path,count() AS requests,countIf(status >= 400) AS errors,min(event_time) AS first_seen,max(event_time) AS last_seen {base} AND path != '' GROUP BY path ORDER BY requests DESC,path ASC LIMIT 12", parameters=params))
        recent = _rows(client.query(f"SELECT event_time AS timestamp,method,path,status {base} ORDER BY event_time DESC LIMIT 50", parameters=params))
        st = status[0] if status else {"s2": 0, "s3": 0, "s4": 0, "s5": 0, "total": 0}
        return {
            "total_requests": int(st["total"]),
            "series": [{"timestamp": _iso_utc(row["timestamp"]), "requests": int(row["requests"]), "errors": int(row["errors"])} for row in series],
            "status_codes": {"2xx": int(st["s2"]), "3xx": int(st["s3"]), "4xx": int(st["s4"]), "5xx": int(st["s5"])},
            "top_paths": [{**row, "requests": int(row["requests"]), "errors": int(row["errors"])} for row in paths],
            "recent_requests": [{"timestamp": _iso_utc(row["timestamp"]), "method": row["method"] or "—", "path": row["path"] or "—", "status": row["status"]} for row in reversed(recent)],
        }
    finally:
        client.close()


def rare_path_baseline(start: datetime, end: datetime, dataset_id: str = "live") -> list[dict[str, Any]]:
    """Return bounded aggregate evidence for periodic rare-path analysis."""
    client = connect()
    try:
        rows = _rows(client.query(
            """SELECT DISTINCT path, IPv6NumToString(src_ip) AS ip,
                      uniqExact(src_ip) OVER (PARTITION BY path) AS path_ips,
                      uniqExact(toStartOfInterval(event_time, INTERVAL 1 HOUR))
                        OVER (PARTITION BY path) AS temporal_buckets,
                      min(event_time) OVER (PARTITION BY path) AS first_seen,
                      max(event_time) OVER (PARTITION BY path) AS last_seen,
                      count() OVER (PARTITION BY path) AS path_requests
               FROM http_events FINAL
              WHERE event_time >= {start:DateTime64(3)}
                AND event_time <= {end:DateTime64(3)}
                AND dataset_id = {dataset_id:String}
                AND path != ''""",
            parameters={"start": start.astimezone(timezone.utc), "end": end.astimezone(timezone.utc), "dataset_id": dataset_id},
        ))
        population = client.query(
            """SELECT uniqExact(src_ip) AS total_ips
               FROM http_events FINAL
              WHERE event_time >= {start:DateTime64(3)}
                AND event_time <= {end:DateTime64(3)}
                AND dataset_id = {dataset_id:String}""",
            parameters={"start": start.astimezone(timezone.utc), "end": end.astimezone(timezone.utc), "dataset_id": dataset_id},
        )
        total_ips = int(population.result_rows[0][0] or 0) if population.result_rows else 0
        return [{
            "path": canonicalize_path(row["path"]), "ip": _display_ip(row["ip"]),
            "path_ips": int(row["path_ips"]), "total_ips": total_ips,
            "temporal_buckets": int(row["temporal_buckets"]),
            "first_seen": _iso_utc(row["first_seen"]), "last_seen": _iso_utc(row["last_seen"]),
            "path_requests": int(row["path_requests"]),
        } for row in rows]
    finally:
        client.close()
