"""Durable enrichment requests shared by API and worker processes."""

import asyncio
from datetime import datetime, timezone

from ..db import postgres as postgres_store
from .profiles import ensure_profile_postgres


def enqueue(ip: str) -> bool:
    """Create or revive one request without coupling the caller to a worker."""
    with postgres_store.transaction() as conn:
        row = conn.execute(
            """INSERT INTO enrichment_requests(ip, status, requested_at, last_error)
               VALUES (%s, 'pending', %s, NULL)
               ON CONFLICT (ip) DO UPDATE SET
                 status = CASE WHEN enrichment_requests.status = 'complete'
                               THEN 'pending' ELSE enrichment_requests.status END,
                 requested_at = EXCLUDED.requested_at,
                 last_error = NULL
               RETURNING id, status""",
            (ip, datetime.now(timezone.utc)),
        ).fetchone()
    return bool(row and row["status"] in {"pending", "processing"})


def _claim(limit: int) -> list[dict]:
    with postgres_store.transaction() as conn:
        rows = conn.execute(
            """WITH picked AS (
                 SELECT id FROM enrichment_requests
                 WHERE status = 'pending'
                 ORDER BY requested_at, id
                 FOR UPDATE SKIP LOCKED LIMIT %s
               )
               UPDATE enrichment_requests r
               SET status = 'processing', claimed_at = now(), attempts = attempts + 1
               FROM picked WHERE r.id = picked.id
               RETURNING r.id, host(r.ip) AS ip""",
            (limit,),
        ).fetchall()
    return rows


def _finish(request_id: int, ok: bool, error: str | None) -> None:
    with postgres_store.transaction() as conn:
        conn.execute(
            """UPDATE enrichment_requests
               SET status=%s, completed_at=CASE WHEN %s THEN now() ELSE completed_at END,
                   last_error=%s
               WHERE id=%s""",
            ("complete" if ok else "failed", ok, error[:500] if error else None, request_id),
        )


async def run_enrichment_worker(stop_event: asyncio.Event) -> None:
    """Claim and process API-originated requests in the worker role."""
    while not stop_event.is_set():
        rows = await asyncio.to_thread(_claim, 20)
        if not rows:
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                pass
            continue
        for row in rows:
            data, error = await ensure_profile_postgres(row["ip"], change_reason="api_enrichment")
            await asyncio.to_thread(_finish, row["id"], bool(data and not error), error)
