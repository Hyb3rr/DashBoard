"""PostgreSQL persistence and policy helpers for alerts and their outbox."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta
from typing import Any

from .json_codec import jsonb_value, json_bytes
from .postgres import transaction
from ..core.clock import utcnow

_ALERT_SEVERITY_RANK = {"unknown": 0, "good": 0, "low": 1, "medium": 2, "critical": 3}
CRITICAL_ALERT_REPEAT_COOLDOWN = timedelta(minutes=30)


class AlertRepository:
    """Read and mutate persisted alert and outbox records."""

    @staticmethod
    def encode_cursor(created_at: Any, alert_id: int) -> str:
        """Encode the stable timestamp-and-ID keyset cursor for alert pages."""
        value = {
            "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at),
            "id": int(alert_id),
        }
        return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")

    @staticmethod
    def decode_cursor(cursor: str) -> tuple[str, int]:
        """Validate and decode an alert keyset cursor."""
        try:
            padded = cursor + "=" * (-len(cursor) % 4)
            value = json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
            created_at = str(value["created_at"])
            alert_id = int(value["id"])
            if not created_at or alert_id < 1:
                raise ValueError
            return created_at, alert_id
        except (ValueError, TypeError, KeyError, json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError("invalid alert cursor") from None

    def list(self, severity: str | None = None, status: str | None = None, limit: int = 50,
             offset: int = 0, cursor: str | None = None) -> dict[str, Any]:
        """Return a filtered alert page with a stable next-page cursor."""
        allowed_severity = {"low", "medium", "critical"}
        allowed_status = {"new", "acknowledged", "resolved"}
        severity = severity if severity in allowed_severity else None
        status = status if status in allowed_status else None
        limit = min(max(int(limit), 1), 100)
        offset = max(int(offset), 0)
        filter_conditions = []
        filter_args: list[Any] = []
        if severity:
            filter_conditions.append("severity=%s")
            filter_args.append(severity)
        if status:
            filter_conditions.append("status=%s")
            filter_args.append(status)
        page_conditions = list(filter_conditions)
        page_args = list(filter_args)
        if cursor:
            cursor_created_at, cursor_id = self.decode_cursor(cursor)
            page_conditions.append("(created_at < %s OR (created_at = %s AND id < %s))")
            page_args.extend([cursor_created_at, cursor_created_at, cursor_id])
        identity_guard = "(EXISTS (SELECT 1 FROM ip_profiles p WHERE p.ip = alerts.ip) OR EXISTS (SELECT 1 FROM ip_observations_state o WHERE o.ip = alerts.ip))"
        inventory_guard = "reason_type <> 'initial_inventory'"
        guarded_base_where = f"WHERE {identity_guard} AND {inventory_guard}" + (f" AND {' AND '.join(filter_conditions)}" if filter_conditions else "")
        guarded_page_where = f"WHERE {identity_guard} AND {inventory_guard}" + (f" AND {' AND '.join(page_conditions)}" if page_conditions else "")
        with transaction() as conn:
            total = conn.execute(f"SELECT COUNT(*) AS n FROM alerts {guarded_base_where}", filter_args).fetchone()["n"]
            rows = conn.execute(
                f"SELECT alerts.* FROM alerts {guarded_page_where} ORDER BY created_at DESC, id DESC LIMIT %s OFFSET %s",
                [*page_args, limit + 1, 0 if cursor else offset],
            ).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        next_cursor = self.encode_cursor(rows[-1]["created_at"], rows[-1]["id"]) if has_more and rows else None
        return {"items": [dict(row) for row in rows], "total": int(total or 0), "next_cursor": next_cursor}

    def get(self, alert_id: int) -> dict[str, Any] | None:
        """Fetch one persisted alert by its database ID."""
        with transaction() as conn:
            row = conn.execute("SELECT * FROM alerts WHERE id=%s", (int(alert_id),)).fetchone()
        return dict(row) if row else None

    def set_status(self, alert_id: int, status: str) -> dict[str, Any] | None:
        """Acknowledge or resolve an alert and return its updated row."""
        if status not in {"acknowledged", "resolved"}:
            raise ValueError("unsupported alert status")
        with transaction() as conn:
            row = conn.execute(
                """UPDATE alerts
                   SET status=%s,
                       acknowledged_at=CASE WHEN %s='acknowledged' THEN COALESCE(acknowledged_at, now()) ELSE acknowledged_at END,
                       resolved_at=CASE WHEN %s='resolved' THEN COALESCE(resolved_at, now()) ELSE resolved_at END,
                       updated_at=now()
                 WHERE id=%s
                 RETURNING *""",
                (status, status, status, int(alert_id)),
            ).fetchone()
        return dict(row) if row else None

    def pending(self, limit: int = 50) -> list[dict[str, Any]]:
        """List due alert notifications waiting in the delivery outbox."""
        with transaction() as conn:
            rows = conn.execute(
                "SELECT * FROM alert_outbox WHERE status='pending' AND next_retry_at<=now() ORDER BY id LIMIT %s",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]


def should_create_alert(old_label: str | None, new_label: str) -> bool:
    """Alert only when deterministic classification enters or rises in severity."""
    old = (old_label or "unknown").lower()
    new = (new_label or "unknown").lower()
    return new in {"low", "medium", "critical"} and _ALERT_SEVERITY_RANK.get(new, 0) > _ALERT_SEVERITY_RANK.get(old, 0)


def should_create_critical_recurrence(
    old_label: str | None,
    new_label: str,
    latest_alert_at: datetime | None,
    now: datetime | None = None,
) -> bool:
    """Allow a materially new Critical alert only after the cooldown."""
    if (old_label or "unknown").lower() != "critical" or (new_label or "unknown").lower() != "critical":
        return False
    if latest_alert_at is None:
        return True
    reference = now or utcnow()
    return reference - latest_alert_at >= CRITICAL_ALERT_REPEAT_COOLDOWN


def _alert_evidence_for_classification(classification: dict[str, Any], observation: dict[str, Any]) -> list[Any]:
    """Keep alert evidence aligned with the evidence used for classification."""
    return classification.get("evidence") or observation.get("recent_behavior_evidence") or []


def create_classification_alert(conn, *, dataset_id: str, batch_id: str, ip: str, old_label: str | None,
                                old_score: int | None, classification: dict[str, Any], evidence: list[Any]) -> None:
    """Persist an eligible severity transition or cooled-down Critical recurrence."""
    new_label = str(classification.get("label") or "unknown").lower()
    reason_type = "classification_transition"
    if not should_create_alert(old_label, new_label):
        if not should_create_critical_recurrence(old_label, new_label, None):
            return
        latest = conn.execute(
            "SELECT created_at FROM alerts WHERE ip=%s AND severity='critical' AND reason_type <> 'initial_inventory' ORDER BY created_at DESC LIMIT 1",
            (ip,),
        ).fetchone()
        if not should_create_critical_recurrence(old_label, new_label, latest["created_at"] if latest else None):
            return
        reason_type = "critical_recurrence"
    fingerprint = hashlib.sha256(json_bytes(evidence)).hexdigest()
    dedupe_key = f"classification:{ip}:{new_label}:{reason_type}:{fingerprint}"
    title = f"{new_label.title()} severity raised for {ip}" if reason_type == "classification_transition" else f"Critical activity repeated for {ip}"
    description = (
        f"Deterministic classification changed from {(old_label or 'unknown').lower()} to {new_label}."
        if reason_type == "classification_transition"
        else "Critical classification remains active with materially changed evidence after the alert cooldown."
    )
    conn.execute(
        """INSERT INTO alerts
           (ip,severity,reason_type,title,description,evidence,evidence_fingerprint,
            previous_classification,current_classification,dedupe_key)
           SELECT %s,%s,%s,%s,%s,%s,%s,%s,%s,%s
           WHERE EXISTS (SELECT 1 FROM ip_profiles WHERE ip=%s)
              OR EXISTS (SELECT 1 FROM ip_observations_state WHERE ip=%s)
           ON CONFLICT(dedupe_key) DO NOTHING""",
        (ip, new_label, reason_type, title, description, jsonb_value(evidence), fingerprint,
         jsonb_value({"label": old_label or "unknown", "score": old_score}),
         jsonb_value(classification), dedupe_key, ip, ip),
    )


def persist_classification_alert_and_notification(
    conn,
    *,
    dataset_id: str,
    batch_id: str,
    ip: str,
    old_label: str | None,
    old_score: int | None,
    classification: dict[str, Any],
    evidence: list[Any],
    created_at=None,
) -> None:
    """Persist classification alerts and Critical notification outbox rows."""
    create_classification_alert(
        conn,
        dataset_id=dataset_id,
        batch_id=batch_id,
        ip=ip,
        old_label=old_label,
        old_score=old_score,
        classification=classification,
        evidence=evidence,
    )
    if str(classification.get("label") or "unknown").lower() != "critical":
        return
    if (old_label or "unknown").lower() == "critical":
        return
    created_at = created_at or utcnow()
    key = f"classification_critical:{dataset_id}:{ip}:{batch_id}"
    conn.execute(
        """INSERT INTO alert_outbox(ip,event_type,payload,status,attempts,next_retry_at,idempotency_key)
           VALUES (%s,'classification_critical',%s,'pending',0,%s,%s)
           ON CONFLICT(idempotency_key) DO NOTHING""",
        (ip, jsonb_value({"ip": ip, "classification": classification}), created_at, key),
    )
