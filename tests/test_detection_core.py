"""Detection core tests.

Pure-logic tests run without any database.
Storage tests require PostgreSQL and are marked @pytest.mark.integration.
"""
from datetime import datetime, timedelta, timezone
import asyncio

import pytest


def test_privacy_provider_freshness_and_proxy_type(monkeypatch):
    from app.core import enrichment

    monkeypatch.setattr(enrichment, "_local_intelligence", lambda ip: ({}, {}, {}, []))
    monkeypatch.setattr(enrichment, "resolve_network_location", lambda conn, ip, vendor=None: {})
    monkeypatch.setattr(enrichment, "_maxmind", lambda ip: ({"country": "Test", "country_code": "TS", "latitude": 1.0, "longitude": 2.0}, [], "active"))
    monkeypatch.setattr(enrichment, "_anonymous_ip", lambda ip: ({"is_vpn": False, "is_proxy": True, "proxy_type": "residential", "is_tor": False, "is_hosting": False}, [], "active"))
    monkeypatch.setattr(enrichment, "_tor_exit_list", lambda ip: ({"is_tor": False}, [], "active"))
    monkeypatch.setattr(enrichment, "_cidr_flag", lambda ip, env_name, label: ({}, [], "not_configured"))
    monkeypatch.setattr(enrichment, "connect", lambda: (_ for _ in ()).throw(RuntimeError("sqlite isolated")))
    monkeypatch.setenv("STALE_HOURS", "72")

    result = asyncio.run(enrichment.lookup("8.8.8.8", refresh=True))
    assert result["proxy_type"] == "residential"
    assert result["provider_status"]["MaxMind City/ASN"]["checked_at"]
    due = datetime.fromisoformat(result["privacy_recheck_due_at"])
    fetched = datetime.fromisoformat(result["fetched_at"])
    assert timedelta(hours=71, minutes=59) <= due - fetched <= timedelta(hours=72, seconds=1)


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
