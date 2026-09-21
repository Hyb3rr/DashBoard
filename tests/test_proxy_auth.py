import ipaddress

from app.core.proxy_auth import trusted_peer, valid_proxy_identity
from app.core.authorization import has_role, parse_roles, required_role


TRUSTED = (ipaddress.ip_network("10.0.0.0/8"),)


def test_direct_client_cannot_spoof_proxy_identity():
    assert not valid_proxy_identity("192.0.2.10", "analyst@example.com", TRUSTED)


def test_trusted_proxy_with_identity_is_accepted():
    assert valid_proxy_identity("10.2.3.4", "analyst@example.com", TRUSTED)


def test_missing_or_oversized_identity_is_rejected():
    assert not valid_proxy_identity("10.2.3.4", "", TRUSTED)
    assert not valid_proxy_identity("10.2.3.4", "x" * 321, TRUSTED)
    assert not valid_proxy_identity("10.2.3.4", "analyst\nforged: true", TRUSTED)
    assert not valid_proxy_identity("10.2.3.4", "analyst@example.com with-space", TRUSTED)


def test_invalid_peer_is_not_trusted():
    assert not trusted_peer("not-an-ip", TRUSTED)


def test_role_header_is_allowlisted_and_hierarchical():
    assert parse_roles("analyst, viewer") == frozenset({"analyst", "viewer"})
    assert parse_roles("admin unknown") == frozenset({"admin"})
    assert has_role({"analyst"}, "viewer")
    assert not has_role({"viewer"}, "analyst")


def test_mutation_role_policy_is_server_side():
    assert required_role("PATCH", "/api/alerts/123") == "analyst"
    assert required_role("PATCH", "/api/alerts/settings") == "admin"
    assert required_role("POST", "/api/ips/refresh-unknown") == "admin"
    assert required_role("POST", "/api/behavior/events") == "viewer"
    assert required_role("GET", "/api/alerts") is None


def test_prometheus_metrics_render_numeric_process_values_only():
    from app.core import metrics

    metrics.reset()
    metrics.increment("collector.events_ingested", 3)
    metrics.gauge("storage.queue_depth", 2)
    finish = metrics.timed("clickhouse.insert_batch_ms")
    finish()
    output = metrics.prometheus_text()

    assert "sentinel_collector_events_ingested_total 3" in output
    assert "sentinel_storage_queue_depth 2.0" in output
    assert "sentinel_clickhouse_insert_batch_ms_count 1" in output
    assert "password" not in output.lower()
