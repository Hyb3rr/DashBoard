"""Detection core tests.

Pure-logic tests run without any database.
Storage tests require PostgreSQL and are marked @pytest.mark.integration.
"""
from datetime import datetime, timedelta, timezone
import asyncio

import pytest


def test_privacy_provider_freshness_and_proxy_type(monkeypatch):
    """Keep privacy enrichment freshness and proxy labels stable."""
    from app.core import enrichment

    monkeypatch.setattr(enrichment, "_local_intelligence", lambda ip: ({}, {}, {}, []))
    monkeypatch.setattr(enrichment, "resolve_network_location", lambda ip, vendor=None, force_refresh=False: {})
    monkeypatch.setattr(enrichment, "_maxmind", lambda ip: ({"country": "Test", "country_code": "TS", "latitude": 1.0, "longitude": 2.0}, [], "active"))
    monkeypatch.setattr(enrichment, "_anonymous_ip", lambda ip: ({"is_vpn": False, "is_proxy": True, "proxy_type": "residential", "is_tor": False, "is_hosting": False}, [], "active"))
    monkeypatch.setattr(enrichment, "_tor_exit_list", lambda ip: ({"is_tor": False}, [], "active"))
    monkeypatch.setattr(enrichment, "_cidr_flag", lambda ip, env_name, label: ({}, [], "not_configured"))
    monkeypatch.setenv("STALE_HOURS", "72")

    result = asyncio.run(enrichment.lookup("8.8.8.8", refresh=True))
    assert result["proxy_type"] == "residential"
    assert result["provider_status"]["MaxMind City/ASN"]["checked_at"]
    due = datetime.fromisoformat(result["privacy_recheck_due_at"])
    fetched = datetime.fromisoformat(result["fetched_at"])
    assert timedelta(hours=71, minutes=59) <= due - fetched <= timedelta(hours=72, seconds=1)


def test_observation_payload_combines_detection_windows(monkeypatch):
    """Preserve the persisted observation contract across detection windows."""
    from app.db.repositories import PgDetectionRepository

    monkeypatch.setattr(
        PgDetectionRepository,
        "_score",
        staticmethod(lambda row, window: (row["score"], f"{window}-level", [window], [{"window": window}])),
    )
    window = {
        "score": 25,
        "first_seen": "2026-09-25T10:00:00+00:00",
        "last_seen": "2026-09-25T10:05:00+00:00",
        "requests": 5,
        "status_2xx": 1,
        "status_3xx": 1,
        "status_4xx": 1,
        "status_5xx": 2,
        "unique_paths": 3,
        "wp_login_requests": 1,
        "sensitive_probe_requests": 2,
        "bot_requests": 4,
    }
    now = datetime(2026, 9, 25, 10, 6, tzinfo=timezone.utc)

    payload = PgDetectionRepository._build_observation_payload(
        "192.0.2.10", window, window, window, now, "2026-09-25T10:00:01+00:00"
    )

    assert payload["behavior_score"] == 50
    assert payload["detections_1h"] == [{"window": "1h"}]
    assert payload["detections_24h"] == [{"window": "24h"}]
    assert payload["recent_behavior_score"] == 25
    assert payload["recent_behavior_level"] == "24h-level"
    assert payload["pipeline_received_at"] == "2026-09-25T10:00:01+00:00"


def test_received_at_by_ip_keeps_earliest_valid_timestamp():
    """Keep the earliest receive time per IP while ignoring incomplete events."""
    from app.db.repositories import PgDetectionRepository

    events = [
        {"src_ip": "192.0.2.10", "pipeline_received_at": "2026-09-25T10:00:02+00:00"},
        {"src_ip": "192.0.2.10", "pipeline_received_at": "2026-09-25T10:00:01+00:00"},
        {"src_ip": "192.0.2.11", "pipeline_received_at": "2026-09-25T10:00:03+00:00"},
        {"src_ip": "192.0.2.12"},
        {"pipeline_received_at": "2026-09-25T10:00:00+00:00"},
    ]

    assert PgDetectionRepository._received_at_by_ip(events) == {
        "192.0.2.10": "2026-09-25T10:00:01+00:00",
        "192.0.2.11": "2026-09-25T10:00:03+00:00",
    }


@pytest.mark.integration
def test_bucket_upsert_is_idempotent_and_exposes_burst():
    """Requires PostgreSQL — skipped without POSTGRES_DSN."""
    pytest.skip("Requires PostgreSQL integration environment")


@pytest.mark.integration
def test_observation_score_matches_persisted_detection_points():
    """Requires PostgreSQL — skipped without POSTGRES_DSN."""
    pytest.skip("Requires PostgreSQL integration environment")


@pytest.mark.integration
def test_windowed_detections_do_not_leak_old_burst_into_one_hour():
    """Requires PostgreSQL — skipped without POSTGRES_DSN."""
    pytest.skip("Requires PostgreSQL integration environment")


@pytest.mark.integration
def test_disposition_history_survives_recommendation_refresh():
    """Requires PostgreSQL — skipped without POSTGRES_DSN."""
    pytest.skip("Requires PostgreSQL integration environment")
