"""PostgreSQL source offset and collector lease state."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from ..core import metrics
from .postgres import transaction


class CheckpointRepository:
    """PostgreSQL source offset and collector lease state."""

    def load_offset(self, source_id: str, log_key: str) -> int:
        with transaction() as conn:
            row = conn.execute("SELECT last_offset FROM log_sources WHERE source_id=%s", (source_id,)).fetchone()
            if not row:
                conn.execute("INSERT INTO log_sources(source_id,log_key,status) VALUES (%s,%s,'starting')", (source_id, log_key))
                return 0
            return int(row["last_offset"] or 0)

    def status(self, source_id: str, log_key: str, state: str, error: str | None = None) -> None:
        with transaction() as conn:
            conn.execute("""INSERT INTO log_sources(source_id,log_key,status,last_error,updated_at)
                VALUES (%s,%s,%s,%s,now()) ON CONFLICT(source_id) DO UPDATE SET log_key=EXCLUDED.log_key,status=EXCLUDED.status,last_error=EXCLUDED.last_error,updated_at=now()""", (source_id, log_key, state, error))

    def read_status(self, source_id: str) -> dict[str, Any] | None:
        """Read persisted collector control-plane state for API-only workers."""
        with transaction() as conn:
            row = conn.execute(
                """SELECT source_id, log_key, status, last_offset, last_error,
                          last_event_at, lease_owner, lease_expires_at, updated_at
                     FROM log_sources WHERE source_id=%s""",
                (source_id,),
            ).fetchone()
        return dict(row) if row else None

    def acquire(self, source_id: str, log_key: str, owner: str, state: str) -> bool:
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=30)
        with transaction() as conn:
            conn.execute("""INSERT INTO log_sources(source_id,log_key,status,lease_owner,lease_expires_at,updated_at)
                VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT(source_id) DO UPDATE SET log_key=EXCLUDED.log_key,status=EXCLUDED.status,lease_owner=EXCLUDED.lease_owner,lease_expires_at=EXCLUDED.lease_expires_at,updated_at=EXCLUDED.updated_at
                WHERE log_sources.lease_owner=EXCLUDED.lease_owner OR log_sources.lease_expires_at IS NULL OR log_sources.lease_expires_at < EXCLUDED.updated_at""", (source_id, log_key, state, owner, expires, now))
            row = conn.execute("SELECT lease_owner FROM log_sources WHERE source_id=%s", (source_id,)).fetchone()
        return bool(row and row["lease_owner"] == owner)

    def renew(self, source_id: str, owner: str) -> bool:
        with transaction() as conn:
            updated = conn.execute(
                """UPDATE log_sources SET lease_expires_at=%s,updated_at=%s
                   WHERE source_id=%s AND lease_owner=%s
                     AND lease_expires_at > CURRENT_TIMESTAMP
                   RETURNING source_id""",
                (datetime.now(timezone.utc) + timedelta(seconds=30), datetime.now(timezone.utc), source_id, owner),
            ).fetchone()
        return bool(updated)

    def commit_offset(
        self, conn, source_id: str, log_key: str, offset: int, state: str,
        event_at: datetime | None, owner: str,
    ) -> None:
        """Commit a monotonic checkpoint only while the lease is still owned.

        The conditional update is the fencing point. A zero-row update means
        that the source is missing, the lease changed/expired, or the offset
        would move backwards; all of those cases must abort the surrounding
        transaction so the caller cannot acknowledge the batch.
        """
        updated = conn.execute(
            """UPDATE log_sources
                  SET log_key=%s, last_offset=%s, status=%s,
                      last_event_at=COALESCE(%s, last_event_at), updated_at=now()
                WHERE source_id=%s
                  AND lease_owner=%s
                  AND lease_expires_at > CURRENT_TIMESTAMP
                  AND last_offset <= %s
             RETURNING last_offset""",
            (log_key, offset, state, event_at, source_id, owner, offset),
        ).fetchone()
        if not updated:
            metrics.increment("checkpoint_commit_rejected")
            raise CheckpointCommitRejected(source_id, offset)
        metrics.increment("checkpoint_commits")


class CheckpointCommitRejected(RuntimeError):
    """Raised when a worker cannot safely advance a source checkpoint."""

    def __init__(self, source_id: str, offset: int) -> None:
        super().__init__(f"checkpoint commit rejected for {source_id} at offset {offset}")
        self.source_id = source_id
        self.offset = offset


