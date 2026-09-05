"""PostgreSQL persistence boundary for manual AI explanation jobs."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .postgres import transaction


STATUSES = {"pending", "running", "completed", "failed"}
_ALLOWED_TRANSITIONS = {
    "pending": {"running", "failed"},
    "running": {"completed", "failed"},
    "completed": set(),
    "failed": set(),
}


def deterministic_job_id(case_id: str, evidence_fingerprint: str) -> str:
    if not case_id or not evidence_fingerprint:
        raise ValueError("AI job requires case_id and evidence_fingerprint")
    digest = hashlib.sha256(f"{case_id}:{evidence_fingerprint}".encode("utf-8")).hexdigest()[:32]
    return f"job_{digest}"


def _check_transition(current: str, target: str) -> None:
    if current not in STATUSES or target not in STATUSES or target not in _ALLOWED_TRANSITIONS[current]:
        raise ValueError(f"invalid AI job transition: {current} -> {target}")


class AiExplainJobRepository:
    """Small transactional repository; no model or network dependency."""

    def create_or_get(self, case_id: str, evidence_fingerprint: str, case_packet: dict[str, Any] | None = None) -> dict[str, Any]:
        job_id = deterministic_job_id(case_id, evidence_fingerprint)
        with transaction() as conn:
            conn.execute(
                """
                INSERT INTO ai_explain_jobs (job_id,case_id,evidence_fingerprint,case_packet_json)
                VALUES (%s,%s,%s,%s::jsonb)
                ON CONFLICT (case_id,evidence_fingerprint) DO NOTHING
                """,
                (job_id, case_id, evidence_fingerprint, json.dumps(case_packet) if case_packet is not None else None),
            )
            row = conn.execute("SELECT * FROM ai_explain_jobs WHERE job_id=%s", (job_id,)).fetchone()
        if row is None:
            raise RuntimeError("AI job was not readable after create")
        return dict(row)

    def get(self, job_id: str) -> dict[str, Any] | None:
        with transaction() as conn:
            row = conn.execute("SELECT * FROM ai_explain_jobs WHERE job_id=%s", (job_id,)).fetchone()
        return dict(row) if row else None

    def recover_stale_running(self, stale_after_seconds: float = 300.0) -> int:
        """Return abandoned running jobs to pending after a worker crash."""
        seconds = max(1.0, float(stale_after_seconds))
        with transaction() as conn:
            result = conn.execute(
                """UPDATE ai_explain_jobs
                   SET status='pending', started_at=NULL, validation_status='pending',
                       provider_status=NULL, failure_code='stale_worker_recovered'
                   WHERE status='running' AND started_at < now() - (%s * interval '1 second')""",
                (seconds,),
            )
        return int(result.rowcount or 0)

    def health_snapshot(self) -> dict[str, Any]:
        with transaction() as conn:
            row = conn.execute(
                """SELECT count(*) FILTER (WHERE status='pending') AS pending,
                          count(*) FILTER (WHERE status='running') AS running,
                          count(*) FILTER (WHERE status='failed') AS failed,
                          min(requested_at) FILTER (WHERE status='pending') AS oldest_pending,
                          min(started_at) FILTER (WHERE status='running') AS oldest_running
                     FROM ai_explain_jobs""",
            ).fetchone()
        return dict(row or {})

    def claim_pending(self) -> dict[str, Any] | None:
        """Atomically claim one pending job; concurrent workers skip it."""
        with transaction() as conn:
            row = conn.execute(
                """WITH candidate AS (
                       SELECT job_id FROM ai_explain_jobs
                       WHERE status='pending'
                       ORDER BY requested_at, job_id
                       FOR UPDATE SKIP LOCKED
                       LIMIT 1
                   )
                   UPDATE ai_explain_jobs AS jobs
                   SET status='running', started_at=now(), failure_code=NULL,
                       validation_status='pending', provider_status=NULL
                   FROM candidate
                   WHERE jobs.job_id=candidate.job_id
                   RETURNING jobs.*""",
            ).fetchone()
        return dict(row) if row else None

    def transition(self, job_id: str, current_status: str, target_status: str, failure_code: str | None = None) -> dict[str, Any] | None:
        _check_transition(current_status, target_status)
        if target_status == "running":
            fields = "status='running',started_at=now(),failure_code=NULL"
        else:
            fields = "status=%s,completed_at=now(),failure_code=%s"
        with transaction() as conn:
            if target_status == "running":
                row = conn.execute(
                    f"UPDATE ai_explain_jobs SET {fields} WHERE job_id=%s AND status=%s RETURNING *",
                    (job_id, current_status),
                ).fetchone()
            else:
                row = conn.execute(
                    f"UPDATE ai_explain_jobs SET {fields} WHERE job_id=%s AND status=%s RETURNING *",
                    (target_status, failure_code, job_id, current_status),
                ).fetchone()
        return dict(row) if row else None

    def persist_completed(self, job_id: str, analysis: dict[str, Any], validation: dict[str, Any], provenance: dict[str, Any]) -> dict[str, Any] | None:
        with transaction() as conn:
            row = conn.execute(
                """UPDATE ai_explain_jobs
                   SET status='completed', completed_at=now(), validation_status='validated',
                       analysis_json=%s::jsonb, validation_json=%s::jsonb, provenance_json=%s::jsonb,
                       provider_status='received', failure_code=NULL
                   WHERE job_id=%s AND status='running'
                   RETURNING *""",
                (json.dumps(analysis), json.dumps(validation), json.dumps(provenance), job_id),
            ).fetchone()
        return dict(row) if row else None

    def persist_failed(self, job_id: str, failure_code: str, validation_status: str, provider_status: str, provenance: dict[str, Any]) -> dict[str, Any] | None:
        if validation_status not in {"invalid", "unsupported_evidence", "unavailable", "timeout", "too_large"}:
            raise ValueError("unsupported AI failure validation status")
        with transaction() as conn:
            row = conn.execute(
                """UPDATE ai_explain_jobs
                   SET status='failed', completed_at=now(), validation_status=%s,
                       provider_status=%s, failure_code=%s, provenance_json=%s::jsonb
                   WHERE job_id=%s AND status='running'
                   RETURNING *""",
                (validation_status, provider_status, failure_code, json.dumps(provenance), job_id),
            ).fetchone()
        return dict(row) if row else None
