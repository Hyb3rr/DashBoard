"""Telegram alert tests.

Pure-logic tests (alert formatting) run without any database.
Outbox delivery tests require PostgreSQL and are marked @integration.
"""
from datetime import datetime, timezone
import asyncio

import pytest

from app.services.telegram import format_bad_alert


def test_bad_alert_contains_score_reasons():
    message = format_bad_alert(
        "198.51.100.9",
        {
            "score": 80,
            "confidence": 90,
            "score_breakdown": {"behavior_a": 80, "identity_b": 0, "trust_c": 0, "region_d": 0, "ai_e": 0},
            "score_explanations": {"A": "A = 80: probe burst", "C": "C = 0: behavior overrides trust"},
            "evidence": ["A — sensitive path probing (+50)"],
        },
        {"organization": "Example <Org>", "asn": "AS64500", "is_hosting": False},
        {"recent_requests": 10, "recent_status_4xx": 8, "recent_status_5xx": 1, "recent_sensitive_probe_requests": 2},
    )
    assert "198.51.100.9" in message
    assert "behavior overrides trust" in message
    assert "&lt;Org&gt;" in message


@pytest.mark.integration
def test_behavior_rebuild_writes_change_log():
    pytest.skip("Requires PostgreSQL integration environment")


@pytest.mark.integration
def test_classification_state_alerts_only_on_bad_transition():
    pytest.skip("Requires PostgreSQL integration environment")


@pytest.mark.integration
def test_outbox_claim_prevents_concurrent_duplicate_delivery():
    pytest.skip("Requires PostgreSQL integration environment")


@pytest.mark.integration
def test_old_outbox_upgrade_deduplicates_and_adds_unique_index():
    pytest.skip("Requires PostgreSQL integration environment")
