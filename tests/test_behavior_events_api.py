from datetime import datetime, timezone
import ipaddress

import httpx
import pytest

from app.main import app
from app.routers import behavior_events
from app.config import settings


@pytest.fixture(autouse=True)
def mock_storage(monkeypatch):
    monkeypatch.setattr(behavior_events.clickhouse, "insert_behavior_events", lambda rows: {"accepted": len(rows), "duplicates": 0, "conflicts": 0, "rejected": 0, "errors": []})


def payload(**overrides):
    value = {"event_id": "evt-1", "timestamp": datetime.now(timezone.utc).isoformat(), "visitor_id": "vis-1", "session_id": "ses-1", "event_name": "page_view", "path": "/pricing", "engagement_ms": None, "key_event_name": None}
    value.update(overrides)
    return value


async def request(method, url, **kwargs):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        return await client.request(method, url, **kwargs)


@pytest.mark.asyncio
async def test_valid_single_event_is_accepted_without_storage_side_effect():
    response = await request("POST", "/api/behavior/events", json=payload())
    assert response.status_code == 200
    assert response.json()["accepted"] == 1


@pytest.mark.asyncio
async def test_valid_batch_reports_partial_invalid_events():
    response = await request("POST", "/api/behavior/events", json={"events": [payload(event_id="evt-2"), payload(event_id="evt-3", engagement_ms=-1)]})
    assert response.status_code == 200
    assert response.json()["accepted"] == 1
    assert response.json()["rejected"] == 1
    assert response.json()["errors"][0]["index"] == 1


@pytest.mark.asyncio
async def test_endpoint_rejects_wrong_content_type_and_missing_identity():
    wrong = await request("POST", "/api/behavior/events", content="{}", headers={"content-type": "text/plain"})
    missing = await request("POST", "/api/behavior/events", json=payload(session_id=None))
    assert wrong.status_code == 415
    assert missing.status_code == 200
    assert missing.json()["rejected"] == 1


@pytest.mark.asyncio
async def test_endpoint_does_not_accept_client_aggregates_or_future_events():
    aggregate = await request("POST", "/api/behavior/events", json=payload(pageviews=100, engaged=True))
    future = await request("POST", "/api/behavior/events", json=payload(event_id="evt-future", timestamp="2099-01-01T00:00:00Z"))
    assert aggregate.json()["rejected"] == 1
    assert future.json()["rejected"] == 1


@pytest.mark.asyncio
async def test_direct_proxy_headers_are_ignored(monkeypatch):
    captured = []
    monkeypatch.setattr(behavior_events.clickhouse, "insert_behavior_events", lambda rows: captured.extend(rows) or {"accepted": len(rows), "duplicates": 0, "conflicts": 0, "rejected": 0, "errors": []})
    monkeypatch.setattr(settings, "TRUST_PROXY_HEADERS", False)

    response = await request(
        "POST", "/api/behavior/events", json=payload(),
        headers={"CF-IPCountry": "DE", "CF-Bot-Score": "99", "X-Is-VPN": "true", "X-Is-Tor": "true"},
    )

    assert response.status_code == 200
    assert captured[0].get("assigned_country") is None
    assert captured[0].get("cf_bot_score") is None
    assert captured[0].get("is_vpn") is None
    assert captured[0].get("is_tor") is None


@pytest.mark.asyncio
async def test_trusted_ingress_headers_are_normalized(monkeypatch):
    captured = []
    monkeypatch.setattr(behavior_events.clickhouse, "insert_behavior_events", lambda rows: captured.extend(rows) or {"accepted": len(rows), "duplicates": 0, "conflicts": 0, "rejected": 0, "errors": []})
    monkeypatch.setattr(settings, "TRUST_PROXY_HEADERS", True)
    monkeypatch.setattr(settings, "TRUSTED_PROXY_NETWORKS", (ipaddress.ip_network("127.0.0.0/8"),))

    response = await request(
        "POST", "/api/behavior/events", json=payload(),
        headers={"CF-IPCountry": "de", "CF-Bot-Score": "99", "X-Is-VPN": "true", "X-Is-Tor": "0"},
    )

    assert response.status_code == 200
    assert captured[0]["assigned_country"] == "DE"
    assert captured[0]["cf_bot_score"] == 99
    assert captured[0]["is_vpn"] is True
    assert captured[0]["is_tor"] is False


@pytest.mark.asyncio
async def test_malformed_trusted_headers_are_ignored_safely(monkeypatch):
    captured = []
    monkeypatch.setattr(behavior_events.clickhouse, "insert_behavior_events", lambda rows: captured.extend(rows) or {"accepted": len(rows), "duplicates": 0, "conflicts": 0, "rejected": 0, "errors": []})
    monkeypatch.setattr(settings, "TRUST_PROXY_HEADERS", True)
    monkeypatch.setattr(settings, "TRUSTED_PROXY_NETWORKS", (ipaddress.ip_network("127.0.0.0/8"),))

    response = await request(
        "POST", "/api/behavior/events", json=payload(),
        headers={"CF-Bot-Score": "nope", "X-Is-VPN": "maybe"},
    )

    assert response.status_code == 200
    assert captured[0]["cf_bot_score"] is None
    assert captured[0]["is_vpn"] is None
