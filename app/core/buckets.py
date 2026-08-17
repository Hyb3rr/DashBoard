"""Persisted minute-level traffic aggregates used by detection and AI."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta, timezone
import hashlib
import sqlite3


def _minute(value: str) -> str:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    return parsed.replace(second=0, microsecond=0).isoformat()


def _path_hash(path: str | None) -> str:
    return hashlib.sha256((path or "").lower().encode("utf-8")).hexdigest()


def upsert_buckets(conn: sqlite3.Connection, parsed_events: Iterable[dict]) -> set[str]:
    """Apply parsed events to minute buckets; caller owns the transaction."""
    affected: set[str] = set()
    for event in parsed_events:
        timestamp = event.get("timestamp")
        ip = event.get("src_ip")
        if not timestamp or not ip:
            continue
        minute = _minute(timestamp)
        status = int(event.get("status") or 0)
        path = (event.get("path") or "").lower()
        ua = (event.get("user_agent") or "").lower()
        conn.execute(
            """
            INSERT INTO ip_time_buckets
              (ip, bucket_minute, requests, status_2xx, status_3xx, status_4xx, status_5xx, status_403, status_404, post_requests,
               sensitive_hits, wp_login_hits, bot_hits, bytes_sum, first_seen, last_seen)
            VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip, bucket_minute) DO UPDATE SET
              requests = requests + 1,
              status_2xx = status_2xx + excluded.status_2xx,
              status_3xx = status_3xx + excluded.status_3xx,
              status_4xx = status_4xx + excluded.status_4xx,
              status_5xx = status_5xx + excluded.status_5xx,
              status_403 = status_403 + excluded.status_403,
              status_404 = status_404 + excluded.status_404,
              post_requests = post_requests + excluded.post_requests,
              sensitive_hits = sensitive_hits + excluded.sensitive_hits,
              wp_login_hits = wp_login_hits + excluded.wp_login_hits,
              bot_hits = bot_hits + excluded.bot_hits,
              bytes_sum = bytes_sum + excluded.bytes_sum,
              first_seen = MIN(first_seen, excluded.first_seen),
              last_seen = MAX(last_seen, excluded.last_seen)
            """,
            (
                ip, minute,
                int(200 <= status < 300), int(300 <= status < 400),
                int(400 <= status < 500), int(status >= 500), int(status == 403), int(status == 404),
                int((event.get("method") or "").upper() == "POST"),
                int(any(marker in path for marker in (
                    "/.env", "/.git", "wp-config.php", "xmlrpc.php",
                    "phpmyadmin", "adminer", "vendor/phpunit",
                ))),
                int("/wp-login.php" in path),
                int(any(word in ua for word in ("bot", "spider", "crawler", "feedfetcher", "archive.org_bot"))),
                int(event.get("bytes_sent") or 0), timestamp, timestamp,
            ),
        )
        path_inserted = conn.execute(
            "INSERT OR IGNORE INTO ip_time_bucket_paths(ip, bucket_minute, path_hash, path) VALUES (?, ?, ?, ?)",
            (ip, minute, _path_hash(event.get("path")), event.get("path")),
        )
        if path_inserted.rowcount:
            conn.execute(
                "UPDATE ip_time_buckets SET unique_paths_approx = unique_paths_approx + 1 "
                "WHERE ip = ? AND bucket_minute = ?",
                (ip, minute),
            )

        raw_path = event.get("path")
        if raw_path:
            family = status // 100
            conn.execute(
                """
                INSERT INTO ip_path_stats
                  (ip, path, requests, status_2xx, status_3xx, status_4xx,
                   status_5xx, first_seen, last_seen)
                VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip, path) DO UPDATE SET
                  requests = requests + 1,
                  status_2xx = status_2xx + excluded.status_2xx,
                  status_3xx = status_3xx + excluded.status_3xx,
                  status_4xx = status_4xx + excluded.status_4xx,
                  status_5xx = status_5xx + excluded.status_5xx,
                  first_seen = MIN(first_seen, excluded.first_seen),
                  last_seen = MAX(last_seen, excluded.last_seen)
                """,
                (
                    ip,
                    raw_path,
                    int(family == 2),
                    int(family == 3),
                    int(family == 4),
                    int(family >= 5),
                    timestamp,
                    timestamp,
                ),
            )
        affected.add(ip)
    return affected


def _normalise_ips(ip_or_ips: str | Sequence[str] | None) -> tuple[str, ...] | None:
    if ip_or_ips is None:
        return None
    if isinstance(ip_or_ips, str):
        return (ip_or_ips,)
    return tuple(dict.fromkeys(ip_or_ips))


def bucket_sums(
    conn: sqlite3.Connection,
    ip_or_ips: str | Sequence[str] | None = None,
    since: datetime | str | None = None,
    until: datetime | str | None = None,
) -> dict[str, dict]:
    """Return aggregate and rate metrics without touching the events table."""
    ips = _normalise_ips(ip_or_ips)
    where: list[str] = []
    params: list[object] = []
    if ips is not None:
        if not ips:
            return {}
        where.append("ip IN (" + ",".join("?" for _ in ips) + ")")
        params.extend(ips)
    if since is not None:
        value = since.isoformat() if isinstance(since, datetime) else since
        where.append("bucket_minute >= ?")
        params.append(value)
    if until is not None:
        value = until.isoformat() if isinstance(until, datetime) else until
        where.append("bucket_minute < ?")
        params.append(value)
    clause = " WHERE " + " AND ".join(where) if where else ""
    rows = conn.execute(
        "SELECT * FROM ip_time_buckets" + clause + " ORDER BY ip, bucket_minute", params
    ).fetchall()
    result: dict[str, dict] = {}
    for row in rows:
        item = result.setdefault(row["ip"], {
            "requests": 0, "status_2xx": 0, "status_3xx": 0, "status_4xx": 0, "status_5xx": 0,
            "status_403": 0, "status_404": 0, "post_requests": 0,
            "unique_paths": 0, "sensitive_probe_requests": 0, "wp_login_requests": 0,
            "bot_requests": 0, "bytes_sum": 0, "first_seen": None, "last_seen": None,
            "peak_requests_1m": 0, "peak_requests_5m": 0, "_minutes": [],
        })
        for key, target in (("requests", "requests"), ("status_2xx", "status_2xx"),
                            ("status_3xx", "status_3xx"), ("status_4xx", "status_4xx"),
                            ("status_5xx", "status_5xx"), ("unique_paths_approx", "unique_paths"),
                            ("status_403", "status_403"), ("status_404", "status_404"), ("post_requests", "post_requests"),
                            ("sensitive_hits", "sensitive_probe_requests"), ("wp_login_hits", "wp_login_requests"),
                            ("bot_hits", "bot_requests"), ("bytes_sum", "bytes_sum")):
            item[target] += int(row[key] or 0)
        item["first_seen"] = min(x for x in (item["first_seen"], row["first_seen"]) if x) if (item["first_seen"] or row["first_seen"]) else None
        item["last_seen"] = max(x for x in (item["last_seen"], row["last_seen"]) if x) if (item["last_seen"] or row["last_seen"]) else None
        item["peak_requests_1m"] = max(item["peak_requests_1m"], int(row["requests"] or 0))
        item["_minutes"].append((row["bucket_minute"], int(row["requests"] or 0)))
    for item in result.values():
        values = {minute: count for minute, count in item.pop("_minutes")}
        minutes = sorted(values)
        item["peak_requests_5m"] = max(
            (sum(values.get((datetime.fromisoformat(minutes[i].replace("Z", "+00:00")) + timedelta(minutes=offset)).isoformat(), 0) for offset in range(5))
             for i in range(len(minutes))), default=0
        )
    return result


def trim_buckets(conn: sqlite3.Connection, now: datetime | None = None, days: int = 30) -> int:
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=days)
    cur = conn.execute("DELETE FROM ip_time_buckets WHERE bucket_minute < ?", (cutoff.replace(second=0, microsecond=0).isoformat(),))
    conn.execute("DELETE FROM ip_time_bucket_paths WHERE NOT EXISTS (SELECT 1 FROM ip_time_buckets b WHERE b.ip = ip_time_bucket_paths.ip AND b.bucket_minute = ip_time_bucket_paths.bucket_minute)")
    return cur.rowcount
