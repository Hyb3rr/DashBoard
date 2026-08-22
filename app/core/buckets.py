"""Pure in-memory minute-level traffic aggregation helpers.

All DB persistence is handled by PgDetectionRepository (PostgreSQL).
This module provides pure aggregation logic with no database dependency.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
import hashlib


def _minute(value: str) -> str:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    return parsed.replace(second=0, microsecond=0).isoformat()


def _path_hash(path: str | None) -> str:
    return hashlib.sha256((path or "").lower().encode("utf-8")).hexdigest()


def aggregate_events(parsed_events: Iterable[dict]) -> dict[tuple[str, str], dict]:
    """Aggregate parsed event dicts into (ip, minute) bucket deltas.

    Returns a dict keyed by (ip, bucket_minute) with aggregated counters.
    Pure function — no DB interaction.
    """
    bucket_deltas: dict[tuple[str, str], dict] = {}
    for event in parsed_events:
        timestamp = event.get("timestamp")
        ip = event.get("src_ip")
        if not timestamp or not ip:
            continue
        minute = _minute(timestamp)
        status = int(event.get("status") or 0)
        family = status // 100
        path = (event.get("path") or "").lower()
        ua = (event.get("user_agent") or "").lower()
        key = (ip, minute)
        bucket = bucket_deltas.setdefault(key, {
            "requests": 0, "status_2xx": 0, "status_3xx": 0,
            "status_4xx": 0, "status_5xx": 0, "status_403": 0,
            "status_404": 0, "post_requests": 0, "sensitive_hits": 0,
            "wp_login_hits": 0, "bot_hits": 0, "bytes_sum": 0,
            "first_seen": timestamp, "last_seen": timestamp,
        })
        bucket["requests"] += 1
        bucket["status_2xx"] += int(200 <= status < 300)
        bucket["status_3xx"] += int(300 <= status < 400)
        bucket["status_4xx"] += int(400 <= status < 500)
        bucket["status_5xx"] += int(status >= 500)
        bucket["status_403"] += int(status == 403)
        bucket["status_404"] += int(status == 404)
        bucket["post_requests"] += int((event.get("method") or "").upper() == "POST")
        bucket["sensitive_hits"] += int(any(marker in path for marker in (
            "/.env", "/.git", "wp-config.php", "xmlrpc.php", "phpmyadmin", "adminer", "vendor/phpunit",
        )))
        bucket["wp_login_hits"] += int("/wp-login.php" in path)
        bucket["bot_hits"] += int(any(word in ua for word in ("bot", "spider", "crawler", "feedfetcher", "archive.org_bot")))
        bucket["bytes_sum"] += int(event.get("bytes_sent") or 0)
        bucket["first_seen"] = min(bucket["first_seen"], timestamp)
        bucket["last_seen"] = max(bucket["last_seen"], timestamp)
    return bucket_deltas


def bucket_sums_from_rows(rows: list[dict]) -> dict[str, dict]:
    """Compute per-IP aggregate sums from a list of bucket row dicts.

    Equivalent to the old SQLite bucket_sums() query result — pure Python.
    """
    result: dict[str, dict] = {}
    for row in rows:
        ip = str(row.get("ip", ""))
        item = result.setdefault(ip, {
            "requests": 0, "status_2xx": 0, "status_3xx": 0, "status_4xx": 0, "status_5xx": 0,
            "status_403": 0, "status_404": 0, "post_requests": 0,
            "unique_paths": 0, "sensitive_probe_requests": 0, "wp_login_requests": 0,
            "bot_requests": 0, "bytes_sum": 0, "first_seen": None, "last_seen": None,
            "peak_requests_1m": 0, "peak_requests_5m": 0, "_minutes": [],
        })
        for src, dst in (
            ("requests", "requests"), ("status_2xx", "status_2xx"),
            ("status_3xx", "status_3xx"), ("status_4xx", "status_4xx"),
            ("status_5xx", "status_5xx"), ("unique_paths_approx", "unique_paths"),
            ("status_403", "status_403"), ("status_404", "status_404"),
            ("post_requests", "post_requests"), ("sensitive_hits", "sensitive_probe_requests"),
            ("wp_login_hits", "wp_login_requests"), ("bot_hits", "bot_requests"),
            ("bytes_sum", "bytes_sum"),
        ):
            item[dst] += int(row.get(src) or 0)
        fs, ls = row.get("first_seen"), row.get("last_seen")
        item["first_seen"] = min(x for x in (item["first_seen"], fs) if x) if (item["first_seen"] or fs) else None
        item["last_seen"] = max(x for x in (item["last_seen"], ls) if x) if (item["last_seen"] or ls) else None
        item["peak_requests_1m"] = max(item["peak_requests_1m"], int(row.get("requests") or 0))
        bucket_minute = row.get("bucket_minute")
        if bucket_minute:
            item["_minutes"].append((str(bucket_minute), int(row.get("requests") or 0)))
    for item in result.values():
        values = {minute: count for minute, count in item.pop("_minutes")}
        minutes = sorted(values)
        item["peak_requests_5m"] = max(
            (sum(values.get((datetime.fromisoformat(minutes[i].replace("Z", "+00:00")) + timedelta(minutes=offset)).isoformat(), 0) for offset in range(5))
             for i in range(len(minutes))), default=0
        )
    return result
