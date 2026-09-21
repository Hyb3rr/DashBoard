from pathlib import Path
import asyncio

from app.collectors.websocket_collector import RealtimeBus


ROOT = Path(__file__).parents[1]


def test_postgres_change_notification_is_durable_wakeup_only():
    sql = (ROOT / "infra/postgres/033_realtime_change_notify.sql").read_text(encoding="utf-8")
    assert "pg_notify('sentinel_ip_changes', NEW.seq::text)" in sql
    assert "AFTER INSERT ON ip_change_log" in sql
    assert "CREATE TRIGGER ip_change_log_realtime_notify" in sql


def test_realtime_listener_is_started_only_by_api_facing_roles():
    source = (ROOT / "app/main.py").read_text(encoding="utf-8")
    assert 'if APP_ROLE in {"all", "api"}' in source
    assert "PostgresRealtimeListener(bus.publish)" in source
    assert "await realtime_listener.stop()" in source


def test_listener_preserves_durable_cursor_contract():
    source = (ROOT / "app/services/realtime_listener.py").read_text(encoding="utf-8")
    assert '"cursor": cursor' in source
    assert '"source": "postgres_notify"' in source
    assert "Clients still fetch the durable cursor" in source


def test_listener_reconnects_with_bounded_backoff_after_database_failure():
    source = (ROOT / "app/services/realtime_listener.py").read_text(encoding="utf-8")
    assert "backoff = 1.0" in source
    assert "backoff = min(30.0, backoff * 2)" in source
    assert "self._stop.wait(backoff)" in source


def test_listener_exposes_failure_state_for_health_diagnostics():
    source = (ROOT / "app/services/realtime_listener.py").read_text(encoding="utf-8")
    assert '"failures": self._failures' in source
    assert '"last_error": self._last_error' in source
    assert 'self._status = "retrying"' in source


def test_health_includes_realtime_listener_and_degrades_when_not_running():
    source = (ROOT / "app/routers/health.py").read_text(encoding="utf-8")
    assert '"realtime_listener": realtime_info' in source
    assert 'realtime_info.get("status") not in {"running", "disabled"}' in source


def test_realtime_bus_coalesces_pending_cursor_notifications():
    async def scenario():
        realtime_bus = RealtimeBus()
        stream = realtime_bus.subscribe()
        first = asyncio.create_task(stream.__anext__())
        await asyncio.sleep(0)
        await realtime_bus.publish("ip_changes", {"cursor": 1})
        assert await first == ("ip_changes", {"cursor": 1})
        await realtime_bus.publish("ip_changes", {"cursor": 2})
        await realtime_bus.publish("ip_changes", {"cursor": 3})
        assert await stream.__anext__() == ("ip_changes", {"cursor": 3})
        await stream.aclose()

    asyncio.run(scenario())
