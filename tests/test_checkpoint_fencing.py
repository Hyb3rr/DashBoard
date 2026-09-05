"""Native PostgreSQL acceptance tests for checkpoint fencing."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import os
from uuid import uuid4

import pytest

from app.db import postgres
from app.db.repositories import CheckpointCommitRejected, CheckpointRepository


def _require_native() -> None:
    if not os.getenv("POSTGRES_DSN"):
        pytest.skip("POSTGRES_DSN is required")


def _source() -> str:
    return f"pytest-checkpoint-{uuid4().hex}"


def _seed(source: str, owner: str, offset: int = 100, *, expired: bool = False) -> None:
    expires = datetime.now(timezone.utc) + timedelta(minutes=5)
    if expired:
        expires = datetime.now(timezone.utc) - timedelta(minutes=5)
    with postgres.transaction() as conn:
        conn.execute("DELETE FROM log_sources WHERE source_id=%s", (source,))
        conn.execute(
            """INSERT INTO log_sources
               (source_id,log_key,last_offset,status,lease_owner,lease_expires_at)
               VALUES (%s,'access',%s,'live',%s,%s)""",
            (source, offset, owner, expires),
        )


def _read(source: str) -> int:
    with postgres.transaction() as conn:
        row = conn.execute(
            "SELECT last_offset FROM log_sources WHERE source_id=%s", (source,)
        ).fetchone()
    return int(row["last_offset"])


def _commit(source: str, owner: str, offset: int) -> str:
    try:
        with postgres.transaction() as conn:
            CheckpointRepository().commit_offset(
                conn, source, "access", offset, "live", datetime.now(timezone.utc), owner
            )
        return "committed"
    except CheckpointCommitRejected:
        return "rejected"


@pytest.mark.integration
@pytest.mark.failure
def test_checkpoint_is_monotonic_and_fenced():
    _require_native()
    source = _source()
    owner = "owner-a"
    try:
        _seed(source, owner)
        assert _commit(source, owner, 80) == "rejected"
        assert _read(source) == 100
        assert _commit(source, owner, 120) == "committed"
        assert _read(source) == 120
        assert _commit(source, owner, 120) == "committed"
        assert _read(source) == 120

        assert _commit(source, "wrong-owner", 140) == "rejected"
        assert _read(source) == 120

        _seed(source, owner, offset=120, expired=True)
        assert _commit(source, owner, 140) == "rejected"
        assert _read(source) == 120
    finally:
        with postgres.transaction() as conn:
            conn.execute("DELETE FROM log_sources WHERE source_id=%s", (source,))


@pytest.mark.integration
@pytest.mark.failure
def test_checkpoint_race_allows_only_current_lease_owner():
    _require_native()
    source = _source()
    owner = "owner-a"
    try:
        _seed(source, owner)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(
                lambda args: _commit(source, *args),
                ((owner, 120), ("owner-b", 140)),
            ))
        assert sorted(results) == ["committed", "rejected"]
        assert _read(source) == 120
    finally:
        with postgres.transaction() as conn:
            conn.execute("DELETE FROM log_sources WHERE source_id=%s", (source,))
