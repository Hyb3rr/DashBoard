import asyncio
from pathlib import Path

from app.routers import ip_detail


def test_ip_detail_returns_snapshot_and_schedules_missing_enrichment(monkeypatch):
    scheduled = []
    snapshot = {"ip": "8.8.8.8", "enrichment_status": "partial", "network_location": {}}
    monkeypatch.setattr(ip_detail.StateRepository, "get", lambda _self, _ip: snapshot)
    monkeypatch.setattr(ip_detail.collector, "schedule_enrichment", lambda ip: scheduled.append(ip))
    monkeypatch.setattr(ip_detail, "_pg_item", lambda row: row)

    result = asyncio.run(ip_detail.ip_details("8.8.8.8"))

    assert result is snapshot
    assert scheduled == ["8.8.8.8"]


def test_non_public_ip_is_terminal_and_never_schedules_enrichment(monkeypatch):
    scheduled = []
    monkeypatch.setattr(ip_detail.StateRepository, "get", lambda _self, ip: {"ip": ip, "enrichment_status": "complete", "network_location": {}})
    monkeypatch.setattr(ip_detail.collector, "schedule_enrichment", lambda ip: scheduled.append(ip))
    monkeypatch.setattr(ip_detail, "_pg_item", lambda row: row)

    for ip in ("169.254.129.1", "10.0.0.1", "127.0.0.1"):
        asyncio.run(ip_detail.ip_details(ip))

    assert scheduled == []


def test_ip_detail_refresh_never_runs_enrichment_inline(monkeypatch):
    scheduled = []
    snapshot = {"ip": "8.8.8.8", "enrichment_status": "complete", "network_location": {"ip2region": "known"}}
    monkeypatch.setattr(ip_detail.StateRepository, "get", lambda _self, _ip: snapshot)
    monkeypatch.setattr(ip_detail.collector, "schedule_enrichment", lambda ip: scheduled.append(ip))
    monkeypatch.setattr(ip_detail, "_pg_item", lambda row: row)

    result = asyncio.run(ip_detail.ip_details("8.8.8.8", refresh=True))

    assert result is snapshot
    assert scheduled == ["8.8.8.8"]


def test_ip_detail_realtime_contract_filters_by_ip_and_debounces():
    html = (Path(__file__).parents[1] / "app" / "ip_detail.html").read_text(encoding="utf-8")
    assert "new EventSource('/api/stream')" in html
    assert "payload.ips" in html
    assert "},350);" in html
    assert "location.reload" not in html


def test_enrichment_change_log_is_written_on_same_transaction(monkeypatch):
    from app.services import profiles

    class Connection:
        def __init__(self):
            self.executed = []

        def execute(self, sql, params=()):
            self.executed.append((sql, params))

    class Scope:
        def __init__(self, connection):
            self.connection = connection

        def __enter__(self):
            return self.connection

        def __exit__(self, *exc):
            return False

    connection = Connection()
    written = []
    monkeypatch.setattr(profiles, "transaction", lambda: Scope(connection))
    monkeypatch.setattr(profiles.ProfileRepository, "get", lambda _self, _ip: None)
    monkeypatch.setattr(profiles.ProfileRepository, "upsert", lambda _self, data, conn=None: written.append(conn))
    monkeypatch.setattr(profiles.GeoRepository, "persist_resolution", lambda *args, **kwargs: None)
    async def lookup(_ip, attempt, refresh):
        return {"ip": _ip, "enrichment_status": "complete"}
    monkeypatch.setattr(profiles, "lookup", lookup)

    result, error = __import__("asyncio").run(
        profiles.ensure_profile_postgres("192.0.2.30", change_reason="enrichment")
    )

    assert error is None
    assert result["ip"] == "192.0.2.30"
    assert written == [connection]
    assert len(connection.executed) == 1
    assert "ip_change_log" in connection.executed[0][0]


def test_same_profile_refresh_does_not_write_change_log(monkeypatch):
    from app.services import profiles

    class Connection:
        def __init__(self):
            self.executed = []

        def execute(self, sql, params=()):
            self.executed.append((sql, params))

    class Scope:
        def __init__(self, connection):
            self.connection = connection

        def __enter__(self):
            return self.connection

        def __exit__(self, *exc):
            return False

    connection = Connection()
    previous = {"ip": "8.8.8.8", "country": "US", "provider_status": {"feed": {"status": "active", "checked_at": "old"}}, "enrichment_status": "complete"}
    current = {**previous, "provider_status": {"feed": {"status": "active", "checked_at": "new"}}, "fetched_at": "new", "enrichment_attempts": 2}
    monkeypatch.setattr(profiles, "transaction", lambda: Scope(connection))
    monkeypatch.setattr(profiles.ProfileRepository, "get", lambda _self, _ip: previous)
    monkeypatch.setattr(profiles.ProfileRepository, "upsert", lambda _self, data, conn=None: None)
    monkeypatch.setattr(profiles.GeoRepository, "persist_resolution", lambda *args, **kwargs: None)
    async def lookup(_ip, attempt, refresh):
        return current
    monkeypatch.setattr(profiles, "lookup", lookup)

    _, error = asyncio.run(profiles.ensure_profile_postgres("8.8.8.8", refresh=True, change_reason="enrichment"))

    assert error is None
    assert connection.executed == []
