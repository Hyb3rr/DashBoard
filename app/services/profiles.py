"""Profile persistence and classification composition using PostgreSQL."""

from datetime import datetime, timedelta, timezone
import asyncio
import json
import os
import socket

from ..config import settings
from ..core.enrichment import lookup
from ..core.classification_provenance import classification_input_provenance
from ..db.json_codec import jsonb_value as _json
from ..core.intelligence import classify_ip
from .classification import classify_with_rollout_metrics
from ..db.repositories import (
    DispositionRepository,
    GeoRepository,
    ProfileRepository,
    _alert_evidence_for_classification,
    persist_classification_alert_and_notification,
)
from ..db.classification_history_repository import ClassificationHistoryRepository
from ..db.postgres import transaction


_VOLATILE_PROFILE_FIELDS = {
    "fetched_at", "updated_at", "geo_resolved_at", "geo_expires_at",
    "next_retry_at", "privacy_recheck_due_at", "enrichment_attempts",
    "risk_score", "risk_level", "evidence",
}


def _stable_profile_value(value):
    """Remove volatile timestamps recursively before comparing profile values."""
    if isinstance(value, dict):
        return {key: _stable_profile_value(item) for key, item in sorted(value.items())
                if key not in {"checked_at", "fetched_at", "updated_at"}}
    if isinstance(value, list):
        return [_stable_profile_value(item) for item in value]
    return value


def profile_state_changed(previous: dict | None, current: dict) -> bool:
    """Compare semantic enrichment state, excluding timestamps/retry metadata."""
    if not previous:
        return True
    keys = set(current) - _VOLATILE_PROFILE_FIELDS - {"ip", "is_private"}
    return any(
        _stable_profile_value(previous.get(key)) != _stable_profile_value(current.get(key))
        for key in keys
    )


def classification_observation(row: dict) -> dict:
    """Build the stable behavior observation consumed by IP classification."""
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


def _reclassify_after_enrichment(conn, ip: str, profile: dict) -> None:
    """Refresh persisted classification when enrichment changes identity signals."""
    observation_result = conn.execute("SELECT payload FROM ip_observations_state WHERE ip=%s", (ip,))
    if observation_result is None:
        return
    observation_row = observation_result.fetchone()
    if not observation_row:
        return
    observation = observation_row["payload"]
    if isinstance(observation, str):
        observation = json.loads(observation)
    if not isinstance(observation, dict):
        return

    previous_result = conn.execute("SELECT label,score FROM ip_classification_state WHERE ip=%s", (ip,))
    previous_row = previous_result.fetchone() if previous_result is not None else None
    region_profile = {}
    ai_profile = None
    classification = classify_with_rollout_metrics(
        profile, observation, region_profile, ai_profile, classifier=classify_ip
    )
    input_provenance = classification_input_provenance(
        profile, observation, region_profile, ai_profile
    )
    conn.execute(
        "UPDATE ip_observations_state SET payload=%s,updated_at=now() WHERE ip=%s",
        (_json(observation), ip),
    )
    old_label = previous_row["label"] if previous_row else None
    old_score = int(previous_row["score"]) if previous_row and previous_row["score"] is not None else None
    score = int(classification["score"])
    changed_at = datetime.now(timezone.utc)
    conn.execute(
        """INSERT INTO ip_classification_state
           (ip,label,score,confidence,input_contract_version,input_fingerprint,updated_at)
           VALUES (%s,%s,%s,%s,%s,%s,%s)
           ON CONFLICT(ip) DO UPDATE SET label=EXCLUDED.label,score=EXCLUDED.score,
            confidence=EXCLUDED.confidence,
            input_contract_version=EXCLUDED.input_contract_version,
            input_fingerprint=EXCLUDED.input_fingerprint,updated_at=EXCLUDED.updated_at""",
        (
            ip, classification["label"], score, int(classification.get("confidence", 0)),
            input_provenance["version"], input_provenance["fingerprint"], changed_at,
        ),
    )
    changed = old_label != classification["label"] or old_score != score
    if changed:
        conn.execute(
            """INSERT INTO ip_change_log(dataset_id,ip,reason,changed_at,old_label,new_label,old_score,new_score)
               VALUES (%s,%s,'enrichment_classification',%s,%s,%s,%s,%s)""",
            (settings.DATASET_LIVE_ID, ip, changed_at, old_label, classification["label"], old_score, score),
        )
        ClassificationHistoryRepository.record_transition(
            conn,
            event_key=f"enrichment:{ip}:{changed_at.isoformat()}",
            dataset_id=settings.DATASET_LIVE_ID,
            ip=ip,
            source="enrichment",
            changed_at=changed_at,
            previous_classification={"label": old_label or "unknown", "score": old_score},
            current_classification=classification,
        )
    alert_result = persist_classification_alert_and_notification(
        conn, dataset_id=settings.DATASET_LIVE_ID, batch_id=f"enrichment:{ip}", ip=ip,
        old_label=old_label, old_score=old_score, classification=classification,
        evidence=_alert_evidence_for_classification(classification, observation),
        created_at=changed_at,
    )
    DispositionRepository.apply_automatic_transition(
        conn,
        ip=ip,
        classification_label=classification.get("label"),
        alert_result=alert_result,
        now=changed_at,
    )


async def ensure_profile_postgres(ip: str, refresh: bool = False, change_reason: str | None = None):
    """Live split-mode enrichment write path."""
    repository = ProfileRepository()
    row = repository.get(ip)
    if row and not refresh and row.get("enrichment_status") == "complete":
        return row, None
    try:
        attempt = int(row.get("enrichment_attempts") or 0) + 1 if row else 1
        data = await lookup(ip, attempt=attempt, refresh=refresh)
        with transaction() as conn:
            repository.upsert(data, conn=conn)
            if data.get("network_location"):
                GeoRepository().persist_resolution(ip, data["network_location"], conn=conn)
            _reclassify_after_enrichment(conn, ip, data)
            if change_reason and profile_state_changed(row, data):
                conn.execute(
                    "INSERT INTO ip_change_log(dataset_id,ip,reason,changed_at) VALUES(%s,%s,%s,%s)",
                    (settings.DATASET_LIVE_ID, ip, change_reason, datetime.now(timezone.utc)),
                )
        return repository.get(ip) or data, None
    except Exception as exc:
        return None, f"{ip}: {type(exc).__name__}"


# Maintain compatibility with existing code calling ensure_profile
async def ensure_profile(conn, ip: str, refresh: bool = False):
    """Delegate legacy profile callers to the PostgreSQL enrichment path."""
    return await ensure_profile_postgres(ip, refresh)


def _claim_privacy_refresh_lease(conn, owner: str, now: datetime, lease_until: datetime) -> bool:
    """Atomically claim the privacy refresh lease if it is available."""
    row = conn.execute(
        """INSERT INTO log_sources(source_id,log_key,status,lease_owner,lease_expires_at,updated_at)
           VALUES (%s, 'privacy', 'running', %s, %s, %s)
           ON CONFLICT(source_id) DO UPDATE SET status='running', lease_owner=EXCLUDED.lease_owner,
             lease_expires_at=EXCLUDED.lease_expires_at, updated_at=EXCLUDED.updated_at
           WHERE log_sources.lease_owner = EXCLUDED.lease_owner
              OR log_sources.lease_expires_at IS NULL
              OR log_sources.lease_expires_at <= EXCLUDED.updated_at
           RETURNING lease_owner""",
        ("privacy-refresh", owner, lease_until, now),
    ).fetchone()
    return bool(row)


def _release_privacy_refresh_lease(conn, owner: str, now: datetime) -> None:
    """Release only a lease still owned by this refresh worker."""
    conn.execute(
        """UPDATE log_sources
           SET status='idle', lease_owner=NULL, lease_expires_at=NULL, updated_at=%s
           WHERE source_id=%s AND lease_owner=%s""",
        (now, "privacy-refresh", owner),
    )


async def refresh_due_profiles(conn, limit: int = 100, now: datetime | None = None) -> dict:
    """Refresh stale privacy enrichment with a PG DB lease shared by runners."""
    now = now or datetime.now(timezone.utc)
    owner = f"privacy:{socket.gethostname()}:{os.getpid()}"
    lease_until = now + timedelta(minutes=5)
    source_id = "privacy-refresh"
    
    with transaction() as pg_conn:
        if not _claim_privacy_refresh_lease(pg_conn, owner, now, lease_until):
            return {"status": "leased", "selected": 0, "processed": 0}
    
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
        processed_ips = []
        for start in range(0, len(selected), 12):
            results = await asyncio.gather(*[
                ensure_profile_postgres(ip, refresh=True, change_reason="privacy_updated") for ip in selected[start:start + 12]
            ])
            for ip, (data, error) in zip(selected[start:start + 12], results):
                if data and not error:
                    processed += 1
                    processed_ips.append(ip)
            
        return {"status": "completed", "selected": len(selected), "processed": processed, "processed_ips": processed_ips}
    finally:
        with transaction() as pg_conn:
            _release_privacy_refresh_lease(pg_conn, owner, datetime.now(timezone.utc))
