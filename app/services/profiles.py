"""Profile persistence and classification composition using PostgreSQL."""

from datetime import datetime, timedelta, timezone
import asyncio
import os
import socket
from typing import Any

from ..config.settings import REGION_SEED_PATH
from ..core.enrichment import lookup
from ..db.repositories import GeoRepository, ProfileRepository, RegionRepository
from ..db.postgres import transaction


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


async def ensure_profile_postgres(ip: str, refresh: bool = False):
    """Live split-mode enrichment write path."""
    repository = ProfileRepository()
    row = repository.get(ip)
    if row and not refresh and row.get("enrichment_status") == "complete":
        return row, None
    try:
        attempt = int(row.get("enrichment_attempts") or 0) + 1 if row else 1
        data = await lookup(ip, attempt=attempt, refresh=refresh)
        repository.upsert(data)
        if data.get("network_location"):
            GeoRepository().persist_resolution(ip, data["network_location"])
        return repository.get(ip) or data, None
    except Exception as exc:
        return None, f"{ip}: {type(exc).__name__}"


# Maintain compatibility with existing code calling ensure_profile
async def ensure_profile(conn, ip: str, refresh: bool = False):
    return await ensure_profile_postgres(ip, refresh)


async def refresh_due_profiles(conn, limit: int = 100, now: datetime | None = None) -> dict:
    """Refresh stale privacy enrichment with a PG DB lease shared by runners."""
    now = now or datetime.now(timezone.utc)
    owner = f"privacy:{socket.gethostname()}:{os.getpid()}"
    lease_until = now + timedelta(minutes=5)
    source_id = "privacy-refresh"
    
    with transaction() as pg_conn:
        row = pg_conn.execute("SELECT lease_owner, lease_expires_at FROM log_sources WHERE source_id = %s", (source_id,)).fetchone()
        if row and row["lease_owner"] and row["lease_owner"] != owner:
            try:
                if row["lease_expires_at"] > now:
                    return {"status": "leased", "selected": 0, "processed": 0}
            except Exception:
                pass
        
        pg_conn.execute(
            """INSERT INTO log_sources(source_id,log_key,status,lease_owner,lease_expires_at,updated_at)
               VALUES (%s, 'privacy', 'running', %s, %s, %s)
               ON CONFLICT(source_id) DO UPDATE SET status='running', lease_owner=EXCLUDED.lease_owner,
                 lease_expires_at=EXCLUDED.lease_expires_at, updated_at=EXCLUDED.updated_at""",
            (source_id, owner, lease_until, now),
        )
    
    try:
        with transaction() as pg_conn:
            rows = pg_conn.execute(
                """SELECT o.ip FROM ip_observations_state o LEFT JOIN ip_profiles p ON p.ip=o.ip
                   WHERE p.ip IS NULL OR p.privacy_recheck_due_at IS NULL
                      OR p.privacy_recheck_due_at <= %s
                   ORDER BY COALESCE((o.payload->>'requests')::bigint, 0) DESC, o.ip ASC LIMIT %s""",
                (now, min(max(1, limit), 5000)),
            ).fetchall()
            
        selected = [str(row["ip"]) for row in rows]
        processed = 0
        for start in range(0, len(selected), 12):
            results = await asyncio.gather(*[
                ensure_profile_postgres(ip, refresh=True) for ip in selected[start:start + 12]
            ])
            processed += sum(1 for data, error in results if data and not error)
            
        return {"status": "completed", "selected": len(selected), "processed": processed}
    finally:
        with transaction() as pg_conn:
            pg_conn.execute(
                "UPDATE log_sources SET status='idle', lease_owner=NULL, lease_expires_at=NULL, updated_at=%s WHERE source_id=%s AND lease_owner=%s",
                (datetime.now(timezone.utc), source_id, owner),
            )
