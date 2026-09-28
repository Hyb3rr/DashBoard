import json

import pytest

from app.providers import pg_intel


def test_provider_privacy_history_contains_only_state_transitions():
    """Record add, change, remove, and reactivation events but skip unchanged rows."""
    now = pg_intel._now()
    old_state = {
        "provider": "provider_a", "proxy_type": "vpn", "score": 1.0,
        "metadata": {"region": "a"}, "active": True,
    }
    current = {
        "192.0.2.1/32": {**old_state, "network": "192.0.2.1/32"},
        "192.0.2.2/32": {**old_state, "network": "192.0.2.2/32"},
        "192.0.2.3/32": {**old_state, "network": "192.0.2.3/32", "active": False},
        "192.0.2.4/32": {**old_state, "network": "192.0.2.4/32"},
    }
    incoming = {
        "192.0.2.1/32": dict(old_state),
        "192.0.2.2/32": {**old_state, "score": 2.0},
        "192.0.2.3/32": dict(old_state),
        "192.0.2.5/32": dict(old_state),
    }

    changes = pg_intel._provider_privacy_changes(
        current, incoming, now, "fixture", "vpn", "provider_a", "refresh-1"
    )

    assert {row[4]: row[5] for row in changes} == {
        "192.0.2.2/32": "changed",
        "192.0.2.3/32": "reactivated",
        "192.0.2.5/32": "added",
        "192.0.2.4/32": "removed",
    }
    assert all(row[3] == "provider_a" and row[8] == "refresh-1" for row in changes)


class _Response:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.payload


def test_az0_partial_mirror_result_does_not_promote_snapshot(monkeypatch):
    manifest = {
        "provider": {
            "urls": ["https://bad.example/list", "https://good.example/list"],
            "ip_key": "ips",
        }
    }
    responses = iter((_Response(json.dumps(manifest).encode()), OSError("mirror unavailable"),
                      _Response(json.dumps({"ips": ["198.51.100.10"]}).encode())))
    promoted = []

    def fake_urlopen(_request, timeout):
        response = next(responses)
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(pg_intel, "urlopen", fake_urlopen)
    monkeypatch.setattr(pg_intel, "_privacy", lambda *args, **kwargs: promoted.append((args, kwargs)))

    result = pg_intel.refresh_az0(object(), url="https://manifest.example/manifest")

    assert result["status"] == "partial"
    assert result["providers"]["provider"]["status"] == "partial"
    assert result["providers"]["provider"]["records"] == 1
    assert result["records_upserted"] == 0
    assert promoted == []


def test_device_browser_timing_separates_parse_from_snapshot_engine(monkeypatch, tmp_path):
    payload_path = tmp_path / "device-browser.csv"
    payload_path.write_text("ip,proxyType,score\n192.0.2.10,datacenter,1\n", encoding="utf-8")
    monkeypatch.setattr("app.providers.common.atomic_write", lambda *_args: None)

    def fake_apply(*_args, **_kwargs):
        return {"status": "updated", "total_ms": 1000.0, "current_rows_written": 0}

    monkeypatch.setattr("app.providers.snapshot_diff.apply_privacy_snapshot", fake_apply)
    result = pg_intel.refresh_device_browser(object(), url=str(payload_path), cache=tmp_path / "cache.csv")

    assert result["parse_ms"] < 1000.0
    assert 1000.0 <= result["total_ms"] < 1100.0


@pytest.mark.integration
def test_provider_scoped_privacy_history_does_not_cross_deactivate_providers():
    import os
    import psycopg

    dsn = os.environ["POSTGRES_DSN"]
    conn = psycopg.connect(dsn, autocommit=False)
    source = "__phase6_az0_fixture__"
    try:
        pg_intel._privacy(conn, source, "vpn", ["198.51.100.0/32", "198.51.100.1/32"],
                          provider="provider_a", provider_filter="provider_a", metadata={"fixture": True})
        pg_intel._privacy(conn, source, "vpn", ["203.0.113.0/32"],
                          provider="provider_b", provider_filter="provider_b", metadata={"fixture": True})
        pg_intel._privacy(conn, source, "vpn", ["198.51.100.0/32", "198.51.100.1/32"],
                          provider="provider_a", provider_filter="provider_a", metadata={"fixture": True})
        pg_intel._privacy(conn, source, "vpn", ["198.51.100.0/32"],
                          provider="provider_a", provider_filter="provider_a", metadata={"fixture": True})
        assert conn.execute(
            "SELECT count(*) FROM privacy_networks WHERE source=%s AND kind='vpn' AND provider='provider_b' AND active",
            (source,),
        ).fetchone()[0] == 1
        assert conn.execute(
            "SELECT count(*) FROM privacy_provider_change_history WHERE source=%s",
            (source,),
        ).fetchone()[0] == 4
    finally:
        conn.rollback()
        conn.close()
