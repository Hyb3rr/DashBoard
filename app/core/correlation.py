"""Periodic network-level correlation for possible coordinated campaigns."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
import sqlite3

from .db import encode


SENSITIVE_MARKERS = ("/.env", "/.git", "wp-config.php", "xmlrpc.php", "phpmyadmin", "adminer", "vendor/phpunit")


def _stamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    except ValueError:
        return None


def _is_sensitive(path: str | None) -> bool:
    value = (path or "").lower()
    return any(marker in value for marker in SENSITIVE_MARKERS)


def _cluster_id(key: str, members: list[str]) -> str:
    return hashlib.sha256((key + "|" + "|".join(sorted(members))).encode()).hexdigest()[:24]


def asn_clusters(conn: sqlite3.Connection, since: datetime | str | None = None, overlap_minutes: int = 10) -> list[dict]:
    """Recompute and persist a fresh snapshot of possible ASN campaigns."""
    if since is None:
        since = datetime.now(timezone.utc) - timedelta(days=30)
    since_value = since.isoformat() if isinstance(since, datetime) else str(since)
    rows = conn.execute(
        """SELECT p.ip, p.asn, p.organization, b.bucket_minute, b.requests,
                  b.first_seen, b.last_seen, bp.path
             FROM ip_profiles p
             JOIN ip_time_buckets b ON b.ip=p.ip AND b.bucket_minute>=?
             LEFT JOIN ip_time_bucket_paths bp ON bp.ip=b.ip AND bp.bucket_minute=b.bucket_minute
            WHERE p.asn IS NOT NULL AND trim(p.asn)!=''
            ORDER BY p.asn, p.organization, p.ip, b.bucket_minute""",
        (since_value,),
    ).fetchall()
    groups: dict[tuple[str, str], dict[str, dict]] = defaultdict(dict)
    for row in rows:
        key = (str(row["asn"]).strip(), str(row["organization"] or "").strip().lower())
        item = groups[key].setdefault(row["ip"], {"requests": 0, "paths": set(), "first": None, "last": None})
        item["requests"] += int(row["requests"] or 0)
        if row["path"] and _is_sensitive(row["path"]):
            item["paths"].add(row["path"])
        first, last = _stamp(row["first_seen"]), _stamp(row["last_seen"])
        item["first"] = min(x for x in (item["first"], first) if x) if (item["first"] or first) else None
        item["last"] = max(x for x in (item["last"], last) if x) if (item["last"] or last) else None

    result = []
    now = datetime.now(timezone.utc).isoformat()
    for (asn, organization), members_data in groups.items():
        if len(members_data) < 3:
            continue
        common_paths = set.intersection(*(data["paths"] for data in members_data.values()))
        if not common_paths:
            continue
        first_values = [data["first"] for data in members_data.values() if data["first"]]
        last_values = [data["last"] for data in members_data.values() if data["last"]]
        if not first_values or not last_values:
            continue
        overlap_start, overlap_end = max(first_values), min(last_values)
        if overlap_start > overlap_end + timedelta(minutes=overlap_minutes):
            continue
        members = sorted(members_data)
        score = min(100, len(members) * 10 + len(common_paths) * 15 + 20)
        cluster = {
            "cluster_id": _cluster_id(asn + "|" + organization, members),
            "asn": asn,
            "organization": organization or None,
            "member_ips": members,
            "shared_paths": sorted(common_paths),
            "first_seen": min(first_values).isoformat(),
            "last_seen": max(last_values).isoformat(),
            "campaign_score": score,
            "total_requests": sum(data["requests"] for data in members_data.values()),
            "overlap_start": overlap_start.isoformat(),
            "overlap_end": overlap_end.isoformat(),
            "updated_at": now,
        }
        result.append(cluster)

    conn.execute("DELETE FROM ip_clusters")
    for cluster in result:
        conn.execute(
            """INSERT INTO ip_clusters
              (cluster_id, asn, organization, member_ips_json, shared_paths_json,
               first_seen, last_seen, campaign_score, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (cluster["cluster_id"], cluster["asn"], cluster["organization"],
             encode(cluster["member_ips"]), encode(cluster["shared_paths"]),
             cluster["first_seen"], cluster["last_seen"], cluster["campaign_score"], cluster["updated_at"]),
        )
    conn.commit()
    return result


def cluster_for_ip(conn: sqlite3.Connection, ip: str | None) -> dict | None:
    if not ip:
        return None
    row = conn.execute(
        "SELECT * FROM ip_clusters WHERE member_ips_json LIKE ? ORDER BY campaign_score DESC LIMIT 1",
        (f'%"{ip}"%',),
    ).fetchone()
    if not row:
        return None
    item = dict(row)
    item["member_ips"] = json.loads(item.pop("member_ips_json") or "[]")
    item["shared_paths"] = json.loads(item.pop("shared_paths_json") or "[]")
    return item
