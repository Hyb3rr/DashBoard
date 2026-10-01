import os

import pytest
from psycopg.types.json import Jsonb

from app.providers.snapshot_diff import (
    _shrink_limits,
    _snapshot_change_counts,
    apply_geo_snapshot,
    apply_privacy_snapshot,
    apply_threat_snapshot,
)


def _rows(items):
    """Build privacy snapshot rows for isolated integration fixtures."""
    return [
        (network, "proxy", "DeviceBrowser", proxy_type, score,
         "__phase2_fixture__", None, None, None, Jsonb({"fixture": True}))
        for network, proxy_type, score in items
    ]


@pytest.mark.integration
def test_identical_snapshot_is_a_noop_and_changes_are_delta_only():
    """Verify identical snapshots write nothing and real changes stay delta-only."""
    import psycopg

    dsn = os.environ["POSTGRES_DSN"]
    conn = psycopg.connect(
        dsn, autocommit=False, row_factory=psycopg.rows.dict_row
    )
    try:
        first = apply_privacy_snapshot(
            conn, "__phase2_fixture__", "proxy",
            _rows([("192.0.2.10", "datacenter", 1.0), ("192.0.2.11", "proxy", 2.0)]),
        )
        second = apply_privacy_snapshot(
            conn, "__phase2_fixture__", "proxy",
            _rows([("192.0.2.10", "datacenter", 1.0), ("192.0.2.11", "proxy", 2.0)]),
        )
        changed = apply_privacy_snapshot(
            conn, "__phase2_fixture__", "proxy",
            _rows([("192.0.2.10", "proxy", 3.0), ("192.0.2.12", "proxy", 1.0)]),
        )
        reactivated = apply_privacy_snapshot(
            conn, "__phase2_fixture__", "proxy",
            _rows([("192.0.2.10", "proxy", 3.0), ("192.0.2.11", "proxy", 2.0), ("192.0.2.12", "proxy", 1.0)]),
        )

        assert first["added"] == 2
        assert {"copy_ms", "stage_index_ms", "analyze_ms", "diff_ms", "apply_ms", "history_ms", "total_ms"} <= first.keys()
        assert second["unchanged"] == 2
        assert second["current_rows_written"] == 0
        assert second["history_rows_written"] == 0
        assert changed["added"] == 1
        assert changed["changed"] == 1
        assert changed["removed"] == 1
        assert changed["current_rows_written"] == 3
        assert changed["history_rows_written"] == 3
        assert reactivated["reactivated"] == 1
        assert reactivated["current_rows_written"] == 1
        assert reactivated["history_rows_written"] == 1
    finally:
        conn.rollback()
        conn.close()


@pytest.mark.integration
def test_empty_or_unexpectedly_small_snapshot_is_rejected_without_writes():
    """Reject empty or suspiciously small snapshots before current-state writes."""
    import psycopg

    dsn = os.environ["POSTGRES_DSN"]
    conn = psycopg.connect(dsn, autocommit=False)
    try:
        assert apply_privacy_snapshot(conn, "__phase2_fixture__", "proxy", [])["status"] == "failed"
        seeded = apply_privacy_snapshot(
            conn, "__phase2_fixture__", "proxy",
            _rows([("192.0.2.20", "proxy", 1.0), ("192.0.2.21", "proxy", 1.0), ("192.0.2.22", "proxy", 1.0)]),
        )
        assert seeded["added"] == 3
        rejected = apply_privacy_snapshot(
            conn, "__phase2_fixture__", "proxy",
            _rows([("192.0.2.20", "proxy", 1.0)]),
        )
        assert rejected["status"] == "failed"
        assert rejected["current_rows_written"] == 0
        assert rejected["history_rows_written"] == 0
    finally:
        conn.rollback()
        conn.close()


@pytest.mark.integration
def test_duplicate_stage_input_fails_closed_and_rolls_back():
    """Ensure duplicate staged networks fail without leaving current rows."""
    import psycopg

    dsn = os.environ["POSTGRES_DSN"]
    conn = psycopg.connect(dsn, autocommit=False)
    duplicate_rows = _rows([("192.0.2.30", "proxy", 1.0), ("192.0.2.30", "proxy", 1.0)])
    try:
        with pytest.raises(psycopg.errors.UniqueViolation):
            apply_privacy_snapshot(conn, "__phase2_duplicate_fixture__", "proxy", duplicate_rows)
        conn.rollback()
        count = conn.execute(
            "SELECT count(*) FROM privacy_networks WHERE source=%s AND kind=%s AND network=%s",
            ("__phase2_duplicate_fixture__", "proxy", "192.0.2.30/32"),
        ).fetchone()[0]
        assert count == 0
    finally:
        conn.rollback()
        conn.close()


@pytest.mark.integration
def test_firehol_threat_and_privacy_are_idempotent_and_atomic():
    """Keep FireHOL threat and privacy snapshots idempotent and atomic."""
    import psycopg

    dsn = os.environ["POSTGRES_DSN"]
    conn = psycopg.connect(dsn, autocommit=False)
    source = "__phase3_firehol_fixture__"
    networks = ["198.51.100.10/32", "198.51.100.11/32"]
    rows = [
        (network, "proxy", "FireHOL", "datacenter", None, source,
         None, None, None, Jsonb({"role": "proxy"}))
        for network in networks
    ]
    try:
        first_threat = apply_threat_snapshot(conn, source, "proxy", networks)
        first_privacy = apply_privacy_snapshot(conn, source, "proxy", rows)
        second_threat = apply_threat_snapshot(conn, source, "proxy", networks)
        second_privacy = apply_privacy_snapshot(conn, source, "proxy", rows)
        assert first_threat["added"] == 2
        assert first_privacy["added"] == 2
        assert second_threat["unchanged"] == 2
        assert second_threat["current_rows_written"] == 0
        assert second_privacy["unchanged"] == 2
        assert second_privacy["current_rows_written"] == 0
        assert second_privacy["history_rows_written"] == 0

        conn.execute("SAVEPOINT firehol_atomicity")
        apply_threat_snapshot(conn, source, "proxy", [networks[0], "198.51.100.12/32"])
        with pytest.raises(psycopg.errors.UniqueViolation):
            apply_privacy_snapshot(conn, source, "proxy", rows + [rows[0]])
        conn.execute("ROLLBACK TO SAVEPOINT firehol_atomicity")
        assert conn.execute(
            "SELECT count(*) FROM threat_indicators WHERE source=%s AND category=%s AND active",
            (source, "proxy"),
        ).fetchone()[0] == 2
        assert conn.execute(
            "SELECT count(*) FROM privacy_networks WHERE source=%s AND kind=%s AND active",
            (source, "proxy"),
        ).fetchone()[0] == 2
    finally:
        conn.rollback()
        conn.close()


@pytest.mark.integration
def test_geo_snapshot_is_idempotent_and_applies_only_prefix_deltas():
    """Verify RIR prefix snapshots only write added, changed, or removed rows."""
    import psycopg

    dsn = os.environ["POSTGRES_DSN"]
    conn = psycopg.connect(dsn, autocommit=False)
    source = "__phase4_rir_fixture__"
    first_rows = [
        {"network": "198.51.100.0/25", "rir": "TEST", "country_code": "VN", "metadata": {}},
        {"network": "203.0.113.0/25", "rir": "TEST", "country_code": "SG", "metadata": {}},
    ]
    try:
        first = apply_geo_snapshot(conn, source, first_rows)
        second = apply_geo_snapshot(conn, source, first_rows)
        changed = apply_geo_snapshot(conn, source, [
            {"network": "198.51.100.0/25", "rir": "TEST", "country_code": "US", "metadata": {}},
            {"network": "192.0.2.0/25", "rir": "TEST", "country_code": "JP", "metadata": {}},
        ])
        assert first["added"] == 2
        assert second["unchanged"] == 2
        assert second["current_rows_written"] == 0
        assert changed["added"] == 1
        assert changed["changed"] == 1
        assert changed["removed"] == 1
        assert changed["current_rows_written"] == 3
    finally:
        conn.rollback()
        conn.close()


def test_snapshot_shrink_limits_accept_source_specific_overrides(monkeypatch):
    """Resolve snapshot safety thresholds from provider-specific configuration."""
    monkeypatch.setenv("INTEL_SNAPSHOT_DEVICEBROWSER_MAX_SHRINK_RATIO", "0.25")
    monkeypatch.setenv("INTEL_SNAPSHOT_DEVICEBROWSER_MIN_ROWS", "12")

    assert _shrink_limits("DeviceBrowser") == (0.75, 12)


def test_snapshot_change_counts_skip_removed_scan_for_an_identical_size():
    """Avoid a removed-row query when the staged snapshot is unchanged."""
    class Cursor:
        """Return a fixed diff result while recording executed SQL."""

        def __init__(self):
            """Initialize the fake cursor call log."""
            self.calls = []

        def execute(self, query, args):
            """Capture each query and return the unchanged-row summary."""
            self.calls.append((query, args))
            return self

        def fetchone(self):
            """Return a stable single-row diff summary."""
            return (0, 0, 0, 5)

    cursor = Cursor()
    result = _snapshot_change_counts(
        cursor, "privacy_snapshot_stage", "privacy_networks", "kind",
        "fixture", "proxy", "(p.provider,p.proxy_type,p.score,p.metadata)",
        "(s.provider,s.proxy_type,s.score,s.metadata)", 5, 5,
    )

    assert result["added"] == 0
    assert result["reactivated"] == 0
    assert result["changed"] == 0
    assert result["unchanged"] == 5
    assert result["removed"] == 0
    assert len(cursor.calls) == 1


def test_geo_snapshot_noop_skips_current_state_apply(monkeypatch):
    """Keep an identical RIR snapshot read-only after staging and comparison."""
    import app.providers.snapshot_diff as snapshot_diff

    class Cursor:
        """Provide the active-source count needed by the no-op orchestration path."""

        def __enter__(self):
            """Return this fake cursor as a context manager."""
            return self

        def __exit__(self, *_args):
            """Close the fake cursor context without suppressing errors."""
            return False

        def execute(self, *_args):
            """Accept the source-count query used by the geo snapshot flow."""
            return self

        def fetchone(self):
            """Report the same active-row count as the incoming fixture."""
            return (1,)

    class Connection:
        """Expose the fake database cursor required by the snapshot service."""

        def cursor(self):
            """Return a fresh fake cursor for one snapshot transaction."""
            return Cursor()

    monkeypatch.setattr(snapshot_diff, "_write_geo_snapshot_stage", lambda *_args: {
        "copy_ms": 1.0, "stage_index_ms": 2.0, "analyze_ms": 3.0,
    })
    monkeypatch.setattr(snapshot_diff, "_geo_snapshot_changes", lambda *_args: {
        "added": 0, "reactivated": 0, "changed": 0, "unchanged": 1,
        "removed": 0, "diff_ms": 4.0,
    })
    monkeypatch.setattr(
        snapshot_diff,
        "_apply_geo_snapshot_changes",
        lambda *_args: (_ for _ in ()).throw(AssertionError("no-op must not write current state")),
    )

    result = snapshot_diff.apply_geo_snapshot(
        Connection(), "fixture", [{"network": "192.0.2.0/24"}]
    )

    assert result["status"] == "updated"
    assert result["unchanged"] == 1
    assert result["current_rows_written"] == 0
    assert result["apply_ms"] == 0.0
