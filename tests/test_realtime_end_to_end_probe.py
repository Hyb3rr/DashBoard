import argparse

import pytest

from scripts.ops import realtime_end_to_end_probe as probe


def test_fixture_log_offset_matches_utf8_payload():
    """Keep the synthetic line and acknowledged byte offset deterministic."""
    line, ip, offset = probe._fixture_log()

    assert ip == "192.0.2.241"
    assert '"GET /e2e-probe HTTP/1.1"' in line
    assert offset == len(line.encode("utf-8")) + 1


def test_server_environment_binds_only_the_requested_local_ports(monkeypatch):
    """Configure the child process for its isolated fixture collector source."""
    monkeypatch.setenv("SENTINEL_TEST_SETTING", "preserved")
    args = argparse.Namespace(http_port=8011, websocket_port=8791)

    env = probe._server_environment(args, "probe-source")

    assert env["SENTINEL_TEST_SETTING"] == "preserved"
    assert env["APP_ROLE"] == "all"
    assert env["LOG_WS_URL"] == "ws://127.0.0.1:8791/log-ws"
    assert env["LOG_WS_SOURCE_ID"] == "probe-source"
    assert env["TRUSTED_HOSTS"] == "127.0.0.1,localhost"


def test_probe_result_requires_cursor_to_resolve_to_fixture_ip():
    """Reject a healthy pipeline when its captured SSE cursor belongs elsewhere."""
    result = {
        "checkpoint": 10,
        "expected_checkpoint": 10,
        "pg_observation_rows": 1,
        "clickhouse_events": 1,
        "captured_sse_events": [{"cursor": 7}],
        "bound_ip_change": {"seq": 7, "ip": "192.0.2.242"},
        "source_binding": {
            "checkpoint_matches_fixture": True,
            "observation_matches_fixture": True,
        },
    }

    with pytest.raises(RuntimeError):
        probe._validate_probe_result(result, "192.0.2.241")


def test_probe_result_accepts_causally_bound_cursor():
    """Accept the probe only when the durable cursor belongs to its fixture IP."""
    result = {
        "checkpoint": 10,
        "expected_checkpoint": 10,
        "pg_observation_rows": 1,
        "clickhouse_events": 1,
        "captured_sse_events": [{"cursor": 7}],
        "bound_ip_change": {"seq": 7, "ip": "192.0.2.241"},
        "source_binding": {
            "checkpoint_matches_fixture": True,
            "observation_matches_fixture": True,
        },
    }

    probe._validate_probe_result(result, "192.0.2.241")
