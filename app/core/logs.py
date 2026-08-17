from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import os
import re
import sqlite3

from .db import encode
from .buckets import bucket_sums, upsert_buckets
from .rules import BehaviorContext, run_rules, ruleset_hash
from .change_feed import append_ip_changes
from ..ai.detector import score_import

APACHE_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) [^"]+" '
    r'(?P<status>\d{3}) (?P<bytes>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"$'
)

BOT_WORDS = ("bot", "spider", "crawler", "feedfetcher", "archive.org_bot")
SENSITIVE_PATHS = (
    "/.env",
    "/.git",
    "/wp-config.php",
    "/xmlrpc.php",
    "/phpmyadmin",
    "/adminer",
    "/vendor/phpunit",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_ts(value: str) -> str | None:
    try:
        return datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc).isoformat()
    except ValueError:
        return None


def parse_apache_combined(line: str) -> dict | None:
    match = APACHE_COMBINED.match(line.strip())
    if not match:
        return None
    data = match.groupdict()
    try:
        ip = str(ipaddress.ip_address(data["ip"]))
    except ValueError:
        return None
    return {
        "src_ip": ip,
        "timestamp": _parse_ts(data["ts"]),
        "method": data["method"],
        "path": data["path"],
        "status": int(data["status"]),
        "bytes_sent": None if data["bytes"] == "-" else int(data["bytes"]),
        "referer": None if data["referer"] == "-" else data["referer"],
        "user_agent": None if data["ua"] == "-" else data["ua"],
    }


def _rule_score(ctx: BehaviorContext, window: str) -> tuple[int, str, list, list[dict]]:
    detections = run_rules(ctx, window)
    score = min(sum(item.points for item in detections), 100)
    level = "low" if score < 25 else "medium" if score < 55 else "high" if score < 80 else "critical"
    evidence = [item.evidence for item in detections]
    return score, level, evidence, [item.to_dict() for item in detections]


def _rebuild_observations(conn: sqlite3.Connection, ips: Sequence[str] | None = None) -> None:
    if ips is not None and not ips:
        return
    rows = bucket_sums(conn, ips)
    if not rows:
        # Compatibility for callers/tests that seed events directly instead of
        # going through the ingest pipeline. Normal batches always populate
        # buckets before this function and never take this path.
        where = ""
        params: tuple[str, ...] = ()
        if ips is not None:
            placeholders = ",".join("?" for _ in ips)
            where = f" WHERE src_ip IN ({placeholders})"
            params = tuple(ips)
        legacy_events = conn.execute(
            "SELECT timestamp,src_ip,method,path,status,bytes_sent,referer,user_agent FROM events" + where,
            params,
        ).fetchall()
        if legacy_events:
            upsert_buckets(conn, [dict(event) for event in legacy_events])
            rows = bucket_sums(conn, ips)
    # Detection windows are product semantics, not deployment configuration.
    # LOGS_BEHAVIOR_LOOKBACK_HOURS must not make a 24h attack query include 48h.
    window_now = datetime.now(timezone.utc)
    recent_by_ip = bucket_sums(conn, ips, window_now - timedelta(hours=24))
    one_hour_by_ip = bucket_sums(conn, ips, window_now - timedelta(hours=1))
    now = _now()
    behavior_columns = (
        "requests", "status_4xx", "status_5xx", "unique_paths", "wp_login_requests",
        "sensitive_probe_requests", "bot_requests",
        "behavior_score", "behavior_level", "behavior_evidence_json", "detections_json",
        "recent_requests", "recent_status_2xx", "recent_status_3xx", "recent_status_4xx",
        "recent_status_5xx", "recent_unique_paths", "recent_wp_login_requests",
        "recent_sensitive_probe_requests", "recent_bot_requests", "behavior_score_recent",
        "behavior_level_recent", "behavior_evidence_recent_json",
    )
    changed_ips: list[str] = []
    for ip, row in rows.items():
        old_row = conn.execute(
            "SELECT " + ", ".join(behavior_columns) + " FROM ip_observations WHERE ip=?",
            (ip,),
        ).fetchone()
        old_behavior = tuple(old_row[column] for column in behavior_columns) if old_row else None
        one_hour = one_hour_by_ip.get(ip, {})
        ctx = BehaviorContext(
            requests_1h=one_hour.get("requests", 0), requests_24h=row["requests"],
            peak_requests_1m=one_hour.get("peak_requests_1m"), peak_requests_5m=one_hour.get("peak_requests_5m"),
            status_4xx_ratio_1h=(one_hour.get("status_4xx", 0) / one_hour["requests"] if one_hour.get("requests") else 0),
            unique_paths_1h=one_hour.get("unique_paths", 0), sensitive_probes_1h=one_hour.get("sensitive_probe_requests", 0),
            requests=row["requests"], status_2xx=row["status_2xx"], status_3xx=row["status_3xx"],
            status_4xx=row["status_4xx"], status_5xx=row["status_5xx"], unique_paths=row["unique_paths"],
            wp_login_requests=row["wp_login_requests"], sensitive_probe_requests=row["sensitive_probe_requests"],
            bot_requests=row["bot_requests"], first_seen=row["first_seen"], last_seen=row["last_seen"],
        )
        lifetime_24_score, _, lifetime_24_evidence, lifetime_24_detections = _rule_score(ctx, "24h")
        one_hour_score, _, one_hour_evidence, one_hour_detections = _rule_score(one_hour and BehaviorContext(
            requests_1h=one_hour.get("requests", 0), requests_24h=one_hour.get("requests", 0),
            peak_requests_1m=one_hour.get("peak_requests_1m"), peak_requests_5m=one_hour.get("peak_requests_5m"),
            status_4xx_ratio_1h=(one_hour.get("status_4xx", 0) / one_hour["requests"] if one_hour.get("requests") else 0),
            unique_paths_1h=one_hour.get("unique_paths", 0), sensitive_probes_1h=one_hour.get("sensitive_probe_requests", 0),
            requests=one_hour.get("requests", 0), status_4xx=one_hour.get("status_4xx", 0), status_2xx=one_hour.get("status_2xx", 0),
            status_3xx=one_hour.get("status_3xx", 0), status_5xx=one_hour.get("status_5xx", 0), unique_paths=one_hour.get("unique_paths", 0),
            wp_login_requests=one_hour.get("wp_login_requests", 0), sensitive_probe_requests=one_hour.get("sensitive_probe_requests", 0),
            bot_requests=one_hour.get("bot_requests", 0), first_seen=one_hour.get("first_seen"), last_seen=one_hour.get("last_seen"),
        ) or BehaviorContext(), "1h")
        lifetime_score = min(lifetime_24_score + one_hour_score, 100)
        lifetime_evidence = lifetime_24_evidence + one_hour_evidence
        detections = lifetime_24_detections + one_hour_detections
        level = "low" if lifetime_score < 25 else "medium" if lifetime_score < 55 else "high" if lifetime_score < 80 else "critical"
        recent = recent_by_ip.get(ip)
        recent_ctx = BehaviorContext(
            requests_1h=recent["requests"], requests_24h=recent["requests"],
            peak_requests_1m=recent["peak_requests_1m"], peak_requests_5m=recent["peak_requests_5m"],
            status_4xx_ratio_1h=(recent["status_4xx"] / recent["requests"] if recent["requests"] else 0),
            unique_paths_1h=recent["unique_paths"], sensitive_probes_1h=recent["sensitive_probe_requests"],
            requests=recent["requests"], status_2xx=recent["status_2xx"], status_3xx=recent["status_3xx"],
            status_4xx=recent["status_4xx"], status_5xx=recent["status_5xx"], unique_paths=recent["unique_paths"],
            wp_login_requests=recent["wp_login_requests"], sensitive_probe_requests=recent["sensitive_probe_requests"],
            bot_requests=recent["bot_requests"], first_seen=recent["first_seen"], last_seen=recent["last_seen"],
        ) if recent else None
        recent_24_score, _, recent_24_evidence, recent_24_detections = _rule_score(recent_ctx, "24h") if recent_ctx else (0, "low", [], [])
        recent_1h_score, _, recent_1h_evidence, recent_1h_detections = _rule_score(one_hour and BehaviorContext(
            requests=one_hour.get("requests", 0), requests_1h=one_hour.get("requests", 0), requests_24h=one_hour.get("requests", 0),
            peak_requests_1m=one_hour.get("peak_requests_1m"), peak_requests_5m=one_hour.get("peak_requests_5m"),
            status_4xx_ratio_1h=(one_hour.get("status_4xx", 0) / one_hour["requests"] if one_hour.get("requests") else 0),
            unique_paths=one_hour.get("unique_paths", 0), unique_paths_1h=one_hour.get("unique_paths", 0),
            sensitive_probe_requests=one_hour.get("sensitive_probe_requests", 0), sensitive_probes_1h=one_hour.get("sensitive_probe_requests", 0),
            wp_login_requests=one_hour.get("wp_login_requests", 0), bot_requests=one_hour.get("bot_requests", 0),
            status_2xx=one_hour.get("status_2xx", 0), status_3xx=one_hour.get("status_3xx", 0), status_4xx=one_hour.get("status_4xx", 0), status_5xx=one_hour.get("status_5xx", 0),
        ) or BehaviorContext(), "1h")
        recent_score = min(recent_24_score + recent_1h_score, 100)
        recent_level = "low" if recent_score < 25 else "medium" if recent_score < 55 else "high" if recent_score < 80 else "critical"
        recent_evidence = recent_24_evidence + recent_1h_evidence
        recent_detections = recent_24_detections + recent_1h_detections
        conn.execute(
            """
            INSERT OR REPLACE INTO ip_observations
              (ip,first_seen,last_seen,requests,status_2xx,status_3xx,status_4xx,status_5xx,
               unique_paths,wp_login_requests,sensitive_probe_requests,bot_requests,
               behavior_score,behavior_level,behavior_evidence_json,
               detections_json,detections_recent_json,detections_1h_json,detections_24h_json,
               ruleset_hash,ruleset_hash_1h,ruleset_hash_24h,evaluated_at,evaluated_at_1h,evaluated_at_24h,
               recent_first_seen,recent_last_seen,recent_requests,recent_status_2xx,recent_status_3xx,
               recent_status_4xx,recent_status_5xx,recent_unique_paths,recent_wp_login_requests,
               recent_sensitive_probe_requests,recent_bot_requests,behavior_score_recent,
               behavior_level_recent,behavior_evidence_recent_json,recent_updated_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                ip,
                row["first_seen"], row["last_seen"],
                row["requests"],
                row["status_2xx"] or 0,
                row["status_3xx"] or 0,
                row["status_4xx"] or 0,
                row["status_5xx"] or 0,
                row["unique_paths"] or 0,
                row["wp_login_requests"] or 0,
                row["sensitive_probe_requests"] or 0,
                row["bot_requests"] or 0,
                lifetime_score,
                level,
                encode(lifetime_evidence),
                encode(detections),
                encode(recent_detections),
                encode(recent_1h_detections),
                encode(recent_24_detections),
                ruleset_hash(),
                ruleset_hash(),
                ruleset_hash(),
                now,
                now,
                now,
                recent["first_seen"] if recent else None,
                recent["last_seen"] if recent else None,
                recent["requests"] if recent else 0,
                recent["status_2xx"] if recent else 0,
                recent["status_3xx"] if recent else 0,
                recent["status_4xx"] if recent else 0,
                recent["status_5xx"] if recent else 0,
                recent["unique_paths"] if recent else 0,
                recent["wp_login_requests"] if recent else 0,
                recent["sensitive_probe_requests"] if recent else 0,
                recent["bot_requests"] if recent else 0,
                recent_score if recent else 0,
                recent_level if recent else "low",
                encode(recent_evidence if recent else []),
                now,
                now,
            ),
        )
        new_row = conn.execute(
            "SELECT " + ", ".join(behavior_columns) + " FROM ip_observations WHERE ip=?",
            (ip,),
        ).fetchone()
        new_behavior = tuple(new_row[column] for column in behavior_columns)
        if old_behavior != new_behavior:
            changed_ips.append(ip)
    if changed_ips:
        append_ip_changes(conn, changed_ips, "behavior", now)


def rebuild_observations(conn: sqlite3.Connection) -> None:
    """Recompute behavior observations for the complete event store."""
    _rebuild_observations(conn)


def rebuild_observations_for_ips(conn: sqlite3.Connection, ips: Sequence[str]) -> None:
    """Recompute only the observations affected by a streaming batch."""
    _rebuild_observations(conn, tuple(dict.fromkeys(ips)))


def import_apache_lines(conn: sqlite3.Connection, lines: Iterable[str], source: str) -> dict:
    parsed = 0
    inserted = 0
    skipped = 0
    now = _now()
    offset = 0
    affected_ips: set[str] = set()
    for line in lines:
        raw = line.rstrip("\n")
        line_offset = offset
        offset += len(line.encode("utf-8"))
        if not raw:
            continue
        event = parse_apache_combined(raw)
        if not event:
            skipped += 1
            continue
        parsed += 1
        line_hash = hashlib.sha256(f"{source}\0{line_offset}\0{raw}".encode()).hexdigest()
        cur = conn.execute(
            """
            INSERT OR IGNORE INTO events
              (source,line_hash,raw_line,timestamp,src_ip,method,path,status,bytes_sent,referer,user_agent,source_offset,imported_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                source,
                line_hash,
                raw,
                event["timestamp"],
                event["src_ip"],
                event["method"],
                event["path"],
                event["status"],
                event["bytes_sent"],
                event["referer"],
                event["user_agent"], line_offset,
                now,
            ),
        )
        inserted += cur.rowcount
        if cur.rowcount:
            upsert_buckets(conn, [event])
            affected_ips.add(event["src_ip"])
    # Rebuild only IPs whose event insert succeeded; replaying an identical
    # source/offset must not trigger a full rebuild or a change event.
    rebuild_observations_for_ips(conn, tuple(affected_ips))
    result = {"parsed": parsed, "inserted": inserted, "duplicates": parsed - inserted, "skipped": skipped}
    result["ai_scoring"] = score_import(conn)
    return result


def effective_risk(profile_score: int | None, behavior_score: int | None) -> tuple[int, str]:
    score = min((profile_score or 0) + (behavior_score or 0), 100)
    level = "low" if score < 25 else "medium" if score < 55 else "high" if score < 80 else "critical"
    return score, level
