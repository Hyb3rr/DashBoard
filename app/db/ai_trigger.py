"""PostgreSQL adapter for the replay-safe AI change-feed consumer."""

from __future__ import annotations

import json
from typing import Any

from .postgres import transaction
from ..services.ai_trigger_policy import TRIGGER_CONSUMER, TriggerEvent
from ..core import metrics


class CursorGapError(RuntimeError):
    """The retained change feed no longer covers the consumer cursor."""


MAX_DEFERRED_IPS = 100
_ADMISSION_LOCK_KEY = 81473621
AUTO_EXPLAIN_FEATURE = "critical_alert_auto_explain"


class AiTriggerRepository:
    def auto_explain_enabled(self) -> bool:
        with transaction() as conn:
            row = conn.execute(
                "SELECT enabled FROM ai_feature_settings WHERE feature_key=%s",
                (AUTO_EXPLAIN_FEATURE,),
            ).fetchone()
        return bool(row and row["enabled"])

    def set_auto_explain_enabled(self, enabled: bool) -> bool:
        """Persist the switch and skip old feed work when enabling it."""
        desired = bool(enabled)
        with transaction() as conn:
            row = conn.execute(
                "SELECT enabled FROM ai_feature_settings WHERE feature_key=%s FOR UPDATE",
                (AUTO_EXPLAIN_FEATURE,),
            ).fetchone()
            previous = bool(row and row["enabled"])
            if desired and not previous:
                current = conn.execute(
                    "SELECT COALESCE(MAX(seq), 0) AS current FROM ip_change_log"
                ).fetchone()
                cursor = int(current["current"] or 0)
                conn.execute(
                    """INSERT INTO ai_trigger_cursors (consumer_name,cursor_seq)
                       VALUES (%s,%s)
                       ON CONFLICT (consumer_name) DO UPDATE
                       SET cursor_seq=EXCLUDED.cursor_seq, updated_at=now()""",
                    (TRIGGER_CONSUMER, cursor),
                )
                conn.execute("DELETE FROM ai_trigger_deferred")
            conn.execute(
                """INSERT INTO ai_feature_settings (feature_key,enabled,updated_at)
                   VALUES (%s,%s,now())
                   ON CONFLICT (feature_key) DO UPDATE
                   SET enabled=EXCLUDED.enabled, updated_at=EXCLUDED.updated_at""",
                (AUTO_EXPLAIN_FEATURE, desired),
            )
        return desired

    def read_batch(self, after: int, limit: int = 50) -> tuple[list[TriggerEvent], int]:
        bounded_limit = max(1, min(int(limit), 500))
        with transaction() as conn:
            bounds = conn.execute("SELECT COALESCE(MAX(seq),0) AS current, COALESCE(MIN(seq),0) AS oldest FROM ip_change_log").fetchone()
            current, oldest = int(bounds["current"] or 0), int(bounds["oldest"] or 0)
            if after and oldest and after < oldest - 1:
                raise CursorGapError(f"AI trigger cursor {after} is older than retained feed {oldest}")
            rows = conn.execute("SELECT seq,host(ip) AS ip,reason,old_label,new_label FROM ip_change_log WHERE seq>%s ORDER BY seq LIMIT %s", (int(after), bounded_limit)).fetchall()
        return [TriggerEvent(int(r["seq"]), r["ip"], r["reason"], r["old_label"], r["new_label"]) for r in rows], current

    def get_cursor(self, consumer_name: str = TRIGGER_CONSUMER) -> int:
        with transaction() as conn:
            row = conn.execute("SELECT cursor_seq FROM ai_trigger_cursors WHERE consumer_name=%s", (consumer_name,)).fetchone()
        return int(row["cursor_seq"]) if row else 0

    def record_event(self, event: TriggerEvent, meaningful: bool, consumer_name: str = TRIGGER_CONSUMER) -> str:
        """Advance the feed and atomically admit/coalesce one semantic trigger."""
        with transaction() as conn:
            cursor = conn.execute("SELECT cursor_seq FROM ai_trigger_cursors WHERE consumer_name=%s FOR UPDATE", (consumer_name,)).fetchone()
            current = int(cursor["cursor_seq"]) if cursor else 0
            if event.seq <= current:
                return "duplicate"
            outcome = "ignored"
            if meaningful:
                conn.execute("SELECT pg_advisory_xact_lock(%s)", (_ADMISSION_LOCK_KEY,))
                existing = conn.execute("SELECT event_seq FROM ai_trigger_deferred WHERE ip=%s", (event.ip,)).fetchone()
                if existing:
                    conn.execute("""UPDATE ai_trigger_deferred
                       SET event_seq=%s,reason=%s,old_label=%s,new_label=%s,queued_at=now()
                       WHERE ip=%s AND event_seq<%s""",
                        (event.seq, event.reason, event.old_label, event.new_label, event.ip, event.seq))
                    outcome = "coalesced"
                else:
                    count = conn.execute("SELECT count(*) AS n FROM ai_trigger_deferred").fetchone()
                    if int(count["n"] or 0) >= MAX_DEFERRED_IPS:
                        metrics.increment("ai_trigger.admission_rejected")
                        outcome = "rejected"
                    else:
                        conn.execute("""INSERT INTO ai_trigger_deferred (ip,event_seq,reason,old_label,new_label)
                           VALUES (%s,%s,%s,%s,%s)""",
                            (event.ip, event.seq, event.reason, event.old_label, event.new_label))
                        outcome = "admitted"
            conn.execute("""INSERT INTO ai_trigger_cursors (consumer_name,cursor_seq) VALUES (%s,%s)
               ON CONFLICT (consumer_name) DO UPDATE SET cursor_seq=GREATEST(ai_trigger_cursors.cursor_seq, EXCLUDED.cursor_seq), updated_at=now()""", (consumer_name, event.seq))
        return outcome

    def available_capacity(self, max_pending_jobs: int) -> int:
        limit = max(0, int(max_pending_jobs))
        with transaction() as conn:
            row = conn.execute("SELECT count(*) AS active FROM ai_explain_jobs WHERE status IN ('pending','running')").fetchone()
        return max(0, limit - int(row["active"] or 0))

    def deferred(self, limit: int = 1) -> list[dict[str, Any]]:
        with transaction() as conn:
            rows = conn.execute("SELECT ip,event_seq,reason,old_label,new_label FROM ai_trigger_deferred ORDER BY event_seq,ip LIMIT %s", (max(1, min(int(limit), 50)),)).fetchall()
        return [dict(row) for row in rows]

    def materialize(self, item: dict[str, Any], job_identity: dict[str, str], packet: dict[str, Any], consumer_name: str = TRIGGER_CONSUMER) -> bool:
        """Create a job and remove only the exact deferred version atomically."""
        from .ai_jobs import deterministic_job_id
        with transaction() as conn:
            row = conn.execute("SELECT event_seq FROM ai_trigger_deferred WHERE ip=%s FOR UPDATE", (item["ip"],)).fetchone()
            if not row or int(row["event_seq"]) != int(item["event_seq"]):
                return False
            active = conn.execute("SELECT count(*) AS n FROM ai_explain_jobs WHERE status IN ('pending','running')").fetchone()
            if int(active["n"] or 0) >= 1:
                return False
            conn.execute("""INSERT INTO ai_explain_jobs (job_id,case_id,evidence_fingerprint,case_packet_json)
               VALUES (%s,%s,%s,%s::jsonb) ON CONFLICT (case_id,evidence_fingerprint) DO NOTHING""",
                (deterministic_job_id(job_identity["case_id"], job_identity["evidence_fingerprint"]), job_identity["case_id"], job_identity["evidence_fingerprint"], json.dumps(packet)))
            conn.execute("DELETE FROM ai_trigger_deferred WHERE ip=%s AND event_seq=%s", (item["ip"], item["event_seq"]))
        return True


__all__ = ["AiTriggerRepository", "CursorGapError", "AUTO_EXPLAIN_FEATURE"]


__all__ = [
    "AiTriggerCursorRepository",
    "MEANINGFUL_TRANSITIONS",
    "TRIGGER_CONSUMER",
    "TriggerEvent",
    "build_trigger_identity",
    "is_meaningful_trigger",
]
