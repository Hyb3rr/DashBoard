"""Profile persistence and classification composition.

Keeping these operations outside the route module makes the API layer mostly
about HTTP concerns and gives background jobs one place to reuse profile IO.
"""

from datetime import datetime, timedelta, timezone
import asyncio
import os
import socket

from ..core.db import decode, encode, region_profile
from ..core.enrichment import lookup
from ..core.correlation import cluster_for_ip
from ..core.intelligence import classify_ip
from .classification import build_classification_snapshot


def profile_from_row(row):
    data = dict(row)
    for column, key in (
        ("evidence_json", "evidence"),
        ("source_json", "sources"),
        ("identity_evidence_json", "identity_evidence"),
        ("reputation_json", "reputation"),
        ("provider_errors_json", "provider_errors"),
        ("provider_status_json", "provider_status"),
        ("field_sources_json", "field_sources"),
    ):
        data[key] = decode(data.pop(column))
    return data


def classification_observation(row: dict) -> dict:
    recent_available = row.get("recent_updated_at") is not None
    return {
        "behavior_score": row.get("behavior_score", 0),
        "recent_behavior_score": row.get("behavior_score_recent", row.get("behavior_score", 0)) if recent_available else row.get("behavior_score", 0),
        "requests": row.get("requests", 0),
        "recent_requests": row.get("recent_requests", row.get("requests", 0)) if recent_available else row.get("requests", 0),
        "recent_sensitive_probe_requests": row.get("recent_sensitive_probe_requests", row.get("sensitive_probe_requests", 0)) if recent_available else row.get("sensitive_probe_requests", 0),
        "status_4xx": row.get("status_4xx", 0),
        "status_5xx": row.get("status_5xx", 0),
        "unique_paths": row.get("unique_paths", 0),
        "wp_login_requests": row.get("wp_login_requests", 0),
        "sensitive_probe_requests": row.get("sensitive_probe_requests", 0),
        "bot_requests": row.get("bot_requests", 0),
        "bucket_history_hours": row.get("bucket_history_hours"),
        "rule_coverage": row.get("rule_coverage"),
    }


def ai_profile_for_ip(conn, ip: str | None) -> dict | None:
    if not ip:
        return None
    row = conn.execute("SELECT * FROM ip_ai_scores WHERE ip = ?", (ip,)).fetchone()
    if not row:
        return None
    data = dict(row)
    data["ai_evidence"] = decode(data.pop("ai_evidence_json"))
    return data


def attach_region_and_classification(conn, data: dict, observation: dict | None = None) -> dict:
    snapshot = build_classification_snapshot(conn, data["ip"]) if data.get("ip") else None
    region = snapshot.region if snapshot else region_profile(conn, data.get("country_code"))
    if region:
        data["region_profile"] = region
    ai_profile = snapshot.ai_profile if snapshot else ai_profile_for_ip(conn, data.get("ip"))
    if ai_profile:
        data["ai_profile"] = ai_profile
    cluster = snapshot.cluster if snapshot else cluster_for_ip(conn, data.get("ip"))
    if cluster:
        data["cluster"] = cluster
    if observation is not None and data.get("ip"):
        history = conn.execute(
            "SELECT MIN(bucket_minute) AS first_bucket, MAX(bucket_minute) AS last_bucket FROM ip_time_buckets WHERE ip=?",
            (data["ip"],),
        ).fetchone()
        if history and history["first_bucket"] and history["last_bucket"]:
            try:
                first = datetime.fromisoformat(history["first_bucket"].replace("Z", "+00:00"))
                last = datetime.fromisoformat(history["last_bucket"].replace("Z", "+00:00"))
                observation["bucket_history_hours"] = max(0, (last - first).total_seconds() / 3600)
                observation["rule_coverage"] = observation["bucket_history_hours"] >= 24
            except ValueError:
                pass
    classification = snapshot.classification if snapshot else classify_ip(data, observation, region, ai_profile, cluster)
    data["data_health"] = classification["data_health"]
    from .dispositions import ensure_disposition
    data["disposition"] = ensure_disposition(conn, data["ip"], classification["label"])
    data["classification"] = classification
    data["threat_signal_score"] = classification["score"]
    data["threat_signal_label"] = classification["label"]
    return data


def _db_bool(value):
    return None if value is None else int(bool(value))


def retry_due(row) -> bool:
    if row["core_enrichment_status"] == "complete" and not row["next_retry_at"]:
        return False
    if not row["next_retry_at"]:
        return True
    try:
        return datetime.fromisoformat(row["next_retry_at"]) <= datetime.now(timezone.utc)
    except ValueError:
        return True


def store_profile(conn, data: dict) -> None:
    conn.execute("""INSERT OR REPLACE INTO ip_profiles
      (ip,country,country_code,city,region,latitude,longitude,timezone,asn,organization,isp,
       network_type,ip_prefix,organization_confidence,identity_evidence_json,
       is_hosting,is_vpn,is_proxy,is_tor,proxy_type,abuse_score,abuse_reports,reputation_json,
       enrichment_status,core_enrichment_status,privacy_enrichment_status,threat_enrichment_status,
       provider_errors_json,next_retry_at,enrichment_attempts,
       provider_status_json,field_sources_json,
       risk_score,risk_level,evidence_json,source_json,fetched_at,privacy_recheck_due_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
      data["ip"], data.get("country"), data.get("country_code"), data.get("city"), data.get("region"),
      data.get("latitude"), data.get("longitude"), data.get("timezone"), data.get("asn"), data.get("organization"), data.get("isp"),
      data.get("network_type"), data.get("ip_prefix"), int(data.get("organization_confidence", 0)), encode(data.get("identity_evidence")),
      _db_bool(data.get("is_hosting")), _db_bool(data.get("is_vpn")), _db_bool(data.get("is_proxy")), _db_bool(data.get("is_tor")), data.get("proxy_type"),
      data.get("abuse_score"), data.get("abuse_reports"), encode(data.get("reputation")),
      data.get("enrichment_status", "failed"), data.get("core_enrichment_status", "failed"),
      data.get("privacy_enrichment_status", "unknown"), data.get("threat_enrichment_status", "unknown"),
      encode(data.get("provider_errors")), data.get("next_retry_at"), data.get("enrichment_attempts", 1),
      encode(data.get("provider_status")), encode(data.get("field_sources")),
      data["risk_score"], data["risk_level"], encode(data["evidence"]), encode(data["sources"]), data["fetched_at"], data.get("privacy_recheck_due_at")))


async def ensure_profile(conn, ip: str, refresh: bool = False):
    row = conn.execute("SELECT * FROM ip_profiles WHERE ip = ?", (ip,)).fetchone()
    if row and not refresh and not retry_due(row):
        return profile_from_row(row), None
    try:
        attempt = (row["enrichment_attempts"] if row else 0) + 1
        data = await lookup(ip, attempt=attempt, refresh=refresh)
    except Exception as exc:
        return None, f"{ip}: {type(exc).__name__}"
    store_profile(conn, data)
    return data, None


async def refresh_due_profiles(conn, limit: int = 100, now: datetime | None = None) -> dict:
    """Refresh stale privacy enrichment with a DB lease shared by runners."""
    now = now or datetime.now(timezone.utc)
    owner = f"privacy:{socket.gethostname()}:{os.getpid()}"
    lease_until = now + timedelta(minutes=5)
    source_id = "privacy-refresh"
    row = conn.execute("SELECT lease_owner, lease_expires_at FROM log_sources WHERE source_id = ?", (source_id,)).fetchone()
    if row and row["lease_owner"] and row["lease_owner"] != owner:
        try:
            if datetime.fromisoformat(row["lease_expires_at"]) > now:
                return {"status": "leased", "selected": 0, "processed": 0}
        except (TypeError, ValueError):
            pass
    conn.execute(
        """INSERT INTO log_sources(source_id,log_key,status,lease_owner,lease_expires_at,updated_at)
           VALUES (?, 'privacy', 'running', ?, ?, ?)
           ON CONFLICT(source_id) DO UPDATE SET status='running', lease_owner=excluded.lease_owner,
             lease_expires_at=excluded.lease_expires_at, updated_at=excluded.updated_at""",
        (source_id, owner, lease_until.isoformat(), now.isoformat()),
    )
    conn.commit()
    try:
        rows = conn.execute(
            """SELECT o.ip FROM ip_observations o LEFT JOIN ip_profiles p ON p.ip=o.ip
               WHERE p.ip IS NULL OR p.privacy_recheck_due_at IS NULL
                  OR p.privacy_recheck_due_at <= ?
               ORDER BY COALESCE(o.requests, 0) DESC, o.ip ASC LIMIT ?""",
            (now.isoformat(), min(max(1, limit), 5000)),
        ).fetchall()
        selected = [row["ip"] for row in rows]
        processed = 0
        for start in range(0, len(selected), 12):
            results = await asyncio.gather(*[
                ensure_profile(conn, ip, refresh=True) for ip in selected[start:start + 12]
            ])
            processed += sum(1 for data, error in results if data and not error)
            conn.commit()
        return {"status": "completed", "selected": len(selected), "processed": processed}
    finally:
        conn.execute(
            "UPDATE log_sources SET status='idle', lease_owner=NULL, lease_expires_at=NULL, updated_at=? WHERE source_id=? AND lease_owner=?",
            (datetime.now(timezone.utc).isoformat(), source_id, owner),
        )
        conn.commit()
