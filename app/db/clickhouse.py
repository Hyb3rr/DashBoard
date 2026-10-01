from __future__ import annotations

import os
from datetime import datetime, timezone
import ipaddress
from typing import Any, Iterable
from ..core import metrics
from ..core.path_canonicalization import canonicalize_path


def configured() -> bool:
    """Report whether a ClickHouse host is configured for this process."""
    return bool(os.getenv("CLICKHOUSE_HOST"))


def connect(database: str | None = None):
    """Open a ClickHouse client using the active environment configuration."""
    try:
        import clickhouse_connect
    except ImportError as exc:  # pragma: no cover - optional deployment extra
        raise RuntimeError("clickhouse-connect is required for DATA_BACKEND=split") from exc
    return clickhouse_connect.get_client(
        host=os.getenv("CLICKHOUSE_HOST", "127.0.0.1"),
        port=int(os.getenv("CLICKHOUSE_PORT", "8123")),
        username=os.getenv("CLICKHOUSE_USER", "default"),
        password=os.getenv("CLICKHOUSE_PASSWORD", ""),
        database=database or os.getenv("CLICKHOUSE_DATABASE", "ipintel"),
        secure=os.getenv("CLICKHOUSE_SECURE", "false").lower() in {"1", "true", "yes"},
    )


def health() -> dict[str, Any]:
    """Probe ClickHouse health with one silent retry for transient keep-alive resets."""
    last_exc: Exception | None = None
    for attempt in range(2):
        client = None
        try:
            client = connect()
            client.query("SELECT 1")
            return {"status": "ok"}
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            # First failure may be a keep-alive expiry — retry once silently.
            if attempt == 0:
                continue
        finally:
            if client is not None:
                client.close()
    return {"status": "failed", "error": f"{type(last_exc).__name__}: {last_exc}"[:240]}


class ClickHouseSchemaError(RuntimeError):
    """Raised when ClickHouse has not been migrated to the runtime contract."""


_REQUIRED_SCHEMA = {
    "http_events": {
        "event_time": "DateTime64(3, 'UTC')",
        "ingested_at": "DateTime64(3, 'UTC')",
        "dataset_id": "LowCardinality(String)",
        "source_id": "LowCardinality(String)",
        "source_offset": "UInt64",
        "event_id": "FixedString(64)",
        "src_ip": "IPv6",
        "method": "LowCardinality(String)",
        "path": "String",
        "status": "UInt16",
        "bytes_sent": "UInt64",
        "referer": "String",
        "user_agent": "String",
        "raw_line": "String",
        "visitor_id": "Nullable(String)",
        "identity_method": "LowCardinality(String)",
        "cf_country": "LowCardinality(String)",
        "cf_asn": "UInt32",
        "cf_as_org": "String",
        "cf_bot_score": "Nullable(UInt8)",
        "country_source": "Nullable(String)",
        "cf_js_detection_passed": "Nullable(UInt8)",
        "is_tor": "Nullable(UInt8)",
        "is_vpn": "Nullable(UInt8)",
        "is_proxy": "Nullable(UInt8)",
        "is_hosting": "Nullable(UInt8)",
        "is_mobile": "Nullable(UInt8)",
        "is_scanner": "Nullable(UInt8)",
        "session_id": "Nullable(String)",
        "engaged": "Nullable(UInt8)",
        "engagement_seconds": "Nullable(Float64)",
        "pageviews": "Nullable(UInt32)",
        "key_event_count": "Nullable(UInt32)",
        "geo_confidence": "Nullable(Float64)",
        "geo_conflict": "Nullable(UInt8)",
    },
    "behavior_events": {
        "event_time": "DateTime64(3, 'UTC')",
        "ingested_at": "DateTime64(3, 'UTC')",
        "event_id": "String",
        "visitor_id": "String",
        "session_id": "String",
        "event_name": "LowCardinality(String)",
        "path": "String",
        "engagement_ms": "Nullable(Float64)",
        "key_event_name": "Nullable(String)",
        "payload_hash": "FixedString(64)",
        "assigned_country": "Nullable(String)",
        "country_source": "Nullable(String)",
        "geo_confidence": "Nullable(Float64)",
        "geo_conflict": "Nullable(UInt8)",
        "cf_bot_score": "Nullable(UInt8)",
        "cf_js_detection_passed": "Nullable(UInt8)",
        "is_tor": "Nullable(UInt8)",
        "is_vpn": "Nullable(UInt8)",
        "is_proxy": "Nullable(UInt8)",
        "is_hosting": "Nullable(UInt8)",
        "is_mobile": "Nullable(UInt8)",
        "is_scanner": "Nullable(UInt8)",
    },
}


def verify_schema(client: Any | None = None) -> None:
    """Verify the minimum ClickHouse contract without issuing DDL."""
    owns_client = client is None
    client = client or connect()
    database = os.getenv("CLICKHOUSE_DATABASE", "ipintel")
    try:
        rows = client.query(
            """
            SELECT table, name, type
            FROM system.columns
            WHERE database = {database:String}
              AND table IN {tables:Array(String)}
            """,
            parameters={"database": database, "tables": list(_REQUIRED_SCHEMA)},
        ).result_rows
        actual = {(str(table), str(name)): str(type_) for table, name, type_ in rows}
        missing_tables = sorted({table for table in _REQUIRED_SCHEMA if not any(key[0] == table for key in actual)})
        if missing_tables:
            raise ClickHouseSchemaError(
                "Missing ClickHouse table(s): "
                + ", ".join(missing_tables)
                + ". Run infra/clickhouse migrations before starting the application."
            )
        for table, columns in _REQUIRED_SCHEMA.items():
            for name, expected_type in columns.items():
                actual_type = actual.get((table, name))
                if actual_type is None:
                    raise ClickHouseSchemaError(f"ClickHouse schema mismatch: {table}.{name} is missing.")
                if actual_type != expected_type:
                    raise ClickHouseSchemaError(
                        f"ClickHouse schema mismatch: {table}.{name} expected {expected_type}, found {actual_type}."
                    )
    finally:
        if owns_client:
            client.close()


def ensure_schema() -> None:
    """Verify ClickHouse storage during explicit startup initialization."""
    verify_schema()


def _insert_events_with_client(client: Any, payload: list[dict[str, Any]]) -> int:
    """Serialize and insert one prepared HTTP-event batch through a client."""
    columns = [
        "event_time", "ingested_at", "dataset_id", "source_id", "source_offset",
        "event_id", "src_ip", "method", "path", "status", "bytes_sent",
        "referer", "user_agent", "raw_line", "visitor_id", "identity_method",
        "cf_country", "cf_asn", "cf_as_org", "cf_bot_score",
        "country_source", "cf_js_detection_passed", "is_tor", "is_vpn", "is_proxy",
        "is_hosting", "is_mobile", "is_scanner", "session_id", "engaged",
        "engagement_seconds", "pageviews", "key_event_count", "geo_confidence", "geo_conflict",
    ]
    values = []
    for row in payload:
        values.append([
            row.get("timestamp"), row.get("ingested_at"), row.get("dataset_id", "live"),
            row.get("source_id", ""), int(row.get("source_offset") or 0), row.get("event_id", ""),
            row.get("src_ip", ""), row.get("method", ""), row.get("path", ""),
            int(row.get("status") or 0), int(row.get("bytes_sent") or 0), row.get("referer") or "",
            row.get("user_agent") or "", row.get("raw_line", ""), row.get("visitor_id"),
            row.get("identity_method", "none"), row.get("cf_country", ""), int(row.get("cf_asn") or 0),
            row.get("cf_as_org", ""), row.get("cf_bot_score"), row.get("country_source"),
            row.get("cf_js_detection_passed"), row.get("is_tor"), row.get("is_vpn"), row.get("is_proxy"),
            row.get("is_hosting"), row.get("is_mobile"), row.get("is_scanner"), row.get("session_id"),
            row.get("engaged"), row.get("engagement_seconds"), row.get("pageviews"),
            row.get("key_event_count"), row.get("geo_confidence"), row.get("geo_conflict"),
        ])
    client.insert("http_events", values, column_names=columns)
    metrics.increment("collector.events_ingested", len(payload))
    metrics.increment("clickhouse.insert_batches")
    return len(payload)


class ClickHouseWriter:
    """Owned, reusable writer for the collector storage worker."""

    def __init__(self) -> None:
        """Initialize the reusable client slot owned by the collector worker."""
        self._client: Any | None = None

    def _get_client(self) -> Any:
        """Lazily create and reuse the collector's ClickHouse connection."""
        if self._client is None:
            self._client = connect()
        return self._client

    def insert_events(self, rows: Iterable[dict[str, Any]]) -> int:
        """Insert one event batch and discard a client after any failure."""
        payload = list(rows)
        if not payload:
            return 0
        finish = metrics.timed("clickhouse.insert_batch_ms")
        try:
            return _insert_events_with_client(self._get_client(), payload)
        except Exception:
            self.close()
            metrics.increment("clickhouse.insert_errors")
            raise
        finally:
            finish()

    def close(self) -> None:
        """Close and clear the reusable ClickHouse client if it exists."""
        client, self._client = self._client, None
        if client is not None:
            client.close()


def insert_events(rows: Iterable[dict[str, Any]]) -> int:
    """Insert one event batch using a short-lived ClickHouse client."""
    payload = list(rows)
    if not payload:
        return 0
    finish = metrics.timed("clickhouse.insert_batch_ms")
    client = connect()
    try:
        return _insert_events_with_client(client, payload)
    except Exception:
        metrics.increment("clickhouse.insert_errors")
        raise
    finally:
        finish()
        client.close()


def insert_behavior_events(rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Persist validated behavioral events with explicit pre-insert dedupe."""
    payload = list(rows)
    if not payload:
        return {"accepted": 0, "duplicates": 0, "conflicts": 0, "rejected": 0, "errors": []}
    client = connect()
    try:
        event_ids = [str(row["event_id"]) for row in payload]
        existing_rows = client.query(
            "SELECT event_id, payload_hash FROM behavior_events WHERE event_id IN {event_ids:Array(String)}",
            parameters={"event_ids": event_ids},
        ).result_rows
        existing = {str(row[0]): (row[1].decode() if isinstance(row[1], bytes) else str(row[1])) for row in existing_rows}
        accepted, duplicates, conflicts, errors = [], 0, 0, []
        seen: dict[str, str] = {}
        for index, row in enumerate(payload):
            event_id, payload_hash = str(row["event_id"]), str(row["payload_hash"])
            previous = existing.get(event_id, seen.get(event_id))
            if previous is not None:
                if previous == payload_hash:
                    duplicates += 1
                else:
                    conflicts += 1
                    errors.append({"index": index, "code": "EVENT_ID_CONFLICT"})
                continue
            seen[event_id] = payload_hash
            accepted.append(row)
        if accepted:
            columns = ["event_time", "ingested_at", "event_id", "visitor_id", "session_id", "event_name", "path", "engagement_ms", "key_event_name", "payload_hash", "assigned_country", "country_source", "geo_confidence", "geo_conflict", "cf_bot_score", "cf_js_detection_passed", "is_tor", "is_vpn", "is_proxy", "is_hosting", "is_mobile", "is_scanner"]
            values = [[row["timestamp"], row.get("received_at") or datetime.now(timezone.utc).isoformat(), row["event_id"], row["visitor_id"], row["session_id"], row["event_name"], row["path"], row["engagement_ms"], row["key_event_name"], row["payload_hash"], *[row.get(field) for field in columns[10:]]] for row in accepted]
            client.insert("behavior_events", values, column_names=columns)
        return {"accepted": len(accepted), "duplicates": duplicates, "conflicts": conflicts, "rejected": len(errors), "errors": errors}
    finally:
        client.close()


def behavior_events(start: datetime, end: datetime) -> list[dict[str, Any]]:
    """Read a bounded behavioral event window for offline aggregation."""
    client = connect()
    try:
        result = client.query(
            """SELECT event_id, event_time, ingested_at, payload_hash, visitor_id, session_id, event_name,
                      path, engagement_ms, key_event_name, assigned_country, country_source,
                      geo_confidence, geo_conflict, cf_bot_score, cf_js_detection_passed,
                      is_tor, is_vpn, is_proxy, is_hosting, is_mobile, is_scanner
               FROM behavior_events
               WHERE event_time >= {start:DateTime64(3)}
                 AND event_time < {end:DateTime64(3)}
               ORDER BY event_time ASC, event_id ASC""",
            parameters={"start": start, "end": end},
        )
        rows = []
        for row in result.result_rows:
            rows.append({"event_id": row[0], "event_time": row[1], "ingested_at": row[2], "payload_hash": row[3], "visitor_id": row[4], "session_id": row[5], "event_name": row[6], "path": row[7], "engagement_ms": row[8], "key_event_name": row[9], "assigned_country": row[10], "country_source": row[11], "geo_confidence": row[12], "geo_conflict": row[13], "cf_bot_score": row[14], "cf_js_detection_passed": row[15], "is_tor": row[16], "is_vpn": row[17], "is_proxy": row[18], "is_hosting": row[19], "is_mobile": row[20], "is_scanner": row[21]})
        return rows
    finally:
        client.close()


def country_demand_events(start: datetime, end: datetime, dataset_id: str = "live") -> list[dict[str, Any]]:
    """Read bounded raw observations for the offline country-demand batch only."""
    client = connect()
    try:
        result = client.query(
            """SELECT event_time, path, visitor_id, identity_method, src_ip,
                      cf_country, cf_asn, cf_as_org, cf_bot_score, country_source,
                      cf_js_detection_passed, is_tor, is_vpn, is_proxy, is_hosting,
                      is_mobile, is_scanner, session_id, engaged, engagement_seconds,
                      pageviews, key_event_count, geo_confidence, geo_conflict
                 FROM http_events FINAL
                WHERE event_time >= {start:DateTime64(3)}
                  AND event_time <= {end:DateTime64(3)}
                  AND dataset_id = {dataset_id:String}""",
            parameters={"start": start.astimezone(timezone.utc), "end": end.astimezone(timezone.utc), "dataset_id": dataset_id},
        )
        return _rows(result)
    finally:
        client.close()


def _rows(result) -> list[dict[str, Any]]:
    """Convert a ClickHouse result block into dictionaries by column name."""
    return [dict(zip(result.column_names, row)) for row in result.result_rows]


def _display_ip(value: Any) -> str:
    """Normalize ClickHouse IPv6 storage into its displayable IP form."""
    address = ipaddress.ip_address(str(value))
    return str(getattr(address, "ipv4_mapped", None) or address)


def _iso_utc(value: Any) -> str:
    """Serialize ClickHouse DateTime values with an explicit UTC offset."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return str(value)


def _traffic_filter(start, end, dataset_id, filter_type, filter_value, exclude, allowed_ips):
    """Build parameterized ClickHouse predicates for the selected traffic cohort."""
    conditions = [
        "event_time >= {start:DateTime64(3)}",
        "event_time <= {end:DateTime64(3)}",
        "dataset_id = {dataset_id:String}",
    ]
    parameters: dict[str, Any] = {
        "start": start.astimezone(timezone.utc),
        "end": end.astimezone(timezone.utc),
        "dataset_id": dataset_id,
    }
    if filter_type == "ip":
        conditions.append("src_ip != {filter_value:IPv6}" if exclude else "src_ip = {filter_value:IPv6}")
        address = ipaddress.ip_address(filter_value)
        parameters["filter_value"] = str(
            ipaddress.IPv6Address(f"::ffff:{address}") if address.version == 4 else address
        )
    elif filter_type == "path":
        conditions.append("path != {filter_value:String}" if exclude else "path = {filter_value:String}")
        parameters["filter_value"] = filter_value
    elif filter_type in {"country", "classification"}:
        conditions.append("src_ip IN {allowed_ips:Array(IPv6)}")
        parameters["allowed_ips"] = allowed_ips or []
    return " AND ".join(conditions), parameters


def _query_traffic_aggregates(client, base, bucket_seconds, parameters):
    """Run the five bounded aggregate queries used by the traffic overview."""
    series = client.query(
        f"SELECT toStartOfInterval(event_time, INTERVAL {int(bucket_seconds)} SECOND) AS timestamp, count() AS requests, countIf(status >= 400) AS errors {base} GROUP BY timestamp ORDER BY timestamp",
        parameters=parameters,
    )
    status = client.query(
        f"SELECT countIf(status BETWEEN 200 AND 299) AS s2, countIf(status BETWEEN 300 AND 399) AS s3, countIf(status BETWEEN 400 AND 499) AS s4, countIf(status >= 500) AS s5, count() AS total, uniqExact(src_ip) AS unique_ip_count {base}",
        parameters=parameters,
    )
    paths = client.query(
        f"SELECT path, count() AS requests {base} GROUP BY path ORDER BY requests DESC, path ASC LIMIT 8",
        parameters=parameters,
    )
    ips = client.query(
        f"SELECT src_ip, count() AS requests {base} GROUP BY src_ip ORDER BY requests DESC, src_ip ASC LIMIT 8",
        parameters=parameters,
    )
    country_ips = client.query(
        f"SELECT src_ip, count() AS requests {base} GROUP BY src_ip",
        parameters=parameters,
    )
    return tuple(_rows(result) for result in (series, status, paths, ips, country_ips))


def _country_request_totals(country_rows):
    """Resolve IP country profiles and sum requests into country buckets."""
    from .postgres import countries_for_ips

    profiles = countries_for_ips([row["ip"] for row in country_rows])
    totals: dict[tuple[str, str], int] = {}
    for row in country_rows:
        profile = profiles.get(row["ip"], {})
        key = (profile.get("country_code") or "", profile.get("country") or "Unknown")
        totals[key] = totals.get(key, 0) + row["requests"]
    return totals


def _traffic_response(aggregates):
    """Shape aggregate rows into the dashboard traffic response contract."""
    series_rows, status_rows, path_rows, ip_rows, country_ip_rows = aggregates
    series = [
        {"timestamp": _iso_utc(row["timestamp"]), "requests": int(row["requests"]), "errors": int(row["errors"])}
        for row in series_rows
    ]
    status = status_rows[0] if status_rows else {
        "s2": 0, "s3": 0, "s4": 0, "s5": 0, "total": 0, "unique_ip_count": 0,
    }
    top_paths = [{"path": row["path"], "requests": int(row["requests"]), "ips": []} for row in path_rows]
    top_ips = [{"ip": _display_ip(row["src_ip"]), "requests": int(row["requests"])} for row in ip_rows]
    country_rows = [
        {"ip": _display_ip(row["src_ip"]), "requests": int(row["requests"])}
        for row in country_ip_rows
    ]
    country_totals = _country_request_totals(country_rows)
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
        # Internal handoff: the API pairs this exact raw-event cohort with
        # current PostgreSQL classification state before returning the DTO.
        "_cohort_ips": [row["ip"] for row in country_rows],
    }


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
    """Aggregate traffic in ClickHouse while keeping raw events and identity state in their owners."""
    client = connect()
    try:
        where, params = _traffic_filter(
            start, end, dataset_id, filter_type, filter_value, exclude, allowed_ips
        )
        base = f"FROM http_events FINAL WHERE {where}"
        aggregates = _query_traffic_aggregates(client, base, bucket_seconds, params)
        return _traffic_response(aggregates)
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


def raw_log_tail(start: datetime, end: datetime, limit: int = 100, dataset_id: str = "live",
                 ip: str | None = None, status: int | None = None,
                 before_time: datetime | None = None,
                 before_event_id: str | None = None) -> list[dict[str, Any]]:
    """Return a bounded, read-only raw HTTP event page in time order."""
    client = connect()
    try:
        conditions = [
            "event_time >= {start:DateTime64(3)}",
            "event_time <= {end:DateTime64(3)}",
            "dataset_id = {dataset_id:String}",
        ]
        parameters: dict[str, Any] = {
            "start": start.astimezone(timezone.utc),
            "end": end.astimezone(timezone.utc),
            "dataset_id": dataset_id,
        }
        if ip:
            conditions.append("src_ip = {ip:IPv6}")
            parameters["ip"] = ip
        if status is not None:
            conditions.append("status = {status:UInt16}")
            parameters["status"] = status
        if before_time is not None and before_event_id is not None:
            cursor_time = before_time
            if cursor_time.tzinfo is None:
                cursor_time = cursor_time.replace(tzinfo=timezone.utc)
            conditions.append(
                "(event_time < {before_time:DateTime64(3)} OR "
                "(event_time = {before_time:DateTime64(3)} AND event_id < {before_event_id:String}))"
            )
            parameters["before_time"] = cursor_time.astimezone(timezone.utc)
            parameters["before_event_id"] = before_event_id
        where = " AND ".join(conditions)
        result = client.query(
            f"""SELECT event_id, event_time, ingested_at, src_ip, method, path,
                       status, raw_line, source_id, source_offset
                  FROM http_events FINAL
                 WHERE {where}
                 ORDER BY event_time DESC, event_id DESC
                 LIMIT {max(1, min(int(limit), 500))}""",
            parameters=parameters,
        )
        rows = []
        for row in result.result_rows:
            rows.append({
                "event_id": row[0], "timestamp": _iso_utc(row[1]), "ingested_at": _iso_utc(row[2]),
                "ip": _display_ip(row[3]), "method": row[4] or "—", "path": row[5] or "—",
                "status": int(row[6]), "raw_line": row[7] or "", "source_id": row[8] or "—",
                "source_offset": int(row[9]),
            })
        return list(reversed(rows))
    finally:
        client.close()


def raw_log_ip_suggestions(start: datetime, end: datetime, prefix: str, limit: int = 12,
                           dataset_id: str = "live", status: int | None = None) -> list[str]:
    """Return recent distinct raw-log IPs matching a display-form prefix."""
    client = connect()
    try:
        display_ip = (
            "if(startsWith(IPv6NumToString(src_ip), '::ffff:'), "
            "substring(IPv6NumToString(src_ip), 8), IPv6NumToString(src_ip))"
        )
        conditions = [
            "event_time >= {start:DateTime64(3)}",
            "event_time <= {end:DateTime64(3)}",
            "dataset_id = {dataset_id:String}",
            f"startsWith(lower({display_ip}), lower({{prefix:String}}))",
        ]
        parameters: dict[str, Any] = {
            "start": start.astimezone(timezone.utc),
            "end": end.astimezone(timezone.utc),
            "dataset_id": dataset_id,
            "prefix": prefix,
        }
        if status is not None:
            conditions.append("status = {status:UInt16}")
            parameters["status"] = status
        rows = client.query(
            f"""SELECT src_ip, max(event_time) AS last_seen
                  FROM http_events FINAL
                 WHERE {' AND '.join(conditions)}
                 GROUP BY src_ip
                 ORDER BY last_seen DESC, src_ip ASC
                 LIMIT {max(1, min(int(limit), 12))}""",
            parameters=parameters,
        ).result_rows
        return [_display_ip(row[0]) for row in rows]
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
