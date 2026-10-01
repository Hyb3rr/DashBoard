from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from app.db import clickhouse
from app.routers import raw_logs


def test_raw_log_ip_suggestions_use_window_prefix_and_status(monkeypatch):
    captured = {}

    def suggest(start, end, prefix, **kwargs):
        captured.update(start=start, end=end, prefix=prefix, **kwargs)
        return ["34.27.109.32"]

    monkeypatch.setattr(raw_logs.clickhouse_store, "raw_log_ip_suggestions", suggest)
    result = raw_logs.raw_log_ip_suggestions(prefix="34.2", window=86400, status=404, limit=12)

    assert captured["end"] - captured["start"] == timedelta(hours=24)
    assert captured["prefix"] == "34.2"
    assert captured["status"] == 404
    assert captured["limit"] == 12
    assert result["ips"] == ["34.27.109.32"]


def test_raw_log_ip_suggestions_reject_invalid_prefix():
    with pytest.raises(HTTPException) as error:
        raw_logs.raw_log_ip_suggestions(prefix="34.2%")

    assert error.value.status_code == 400


def test_raw_log_history_page_uses_fixed_window_and_returns_older_cursor(monkeypatch):
    as_of = datetime(2026, 9, 28, 12, tzinfo=timezone.utc)
    events = [
        {"event_id": f"event-{index}", "timestamp": (as_of - timedelta(minutes=index)).isoformat()}
        for index in (2, 1, 0)
    ]
    captured = {}

    def fetch(start, end, **kwargs):
        captured.update(start=start, end=end, **kwargs)
        return events

    monkeypatch.setattr(raw_logs.clickhouse_store, "raw_log_tail", fetch)
    result = raw_logs.raw_logs_tail(
        window=86400, limit=2, as_of=as_of,
        before_time=as_of + timedelta(seconds=1), before_event_id="anchor",
    )

    assert captured["start"] == as_of - timedelta(hours=24)
    assert captured["end"] == as_of
    assert captured["limit"] == 3
    assert captured["before_event_id"] == "anchor"
    assert [event["event_id"] for event in result["events"]] == ["event-1", "event-0"]
    assert result["has_more"] is True
    assert result["next_cursor"] == {
        "before_time": events[1]["timestamp"],
        "before_event_id": "event-1",
    }


def test_raw_log_history_rejects_partial_cursor():
    with pytest.raises(HTTPException) as error:
        raw_logs.raw_logs_tail(before_event_id="event-1")

    assert error.value.status_code == 400


def test_clickhouse_raw_log_query_applies_older_cursor_and_bounded_limit(monkeypatch):
    as_of = datetime(2026, 9, 28, 12, tzinfo=timezone.utc)
    captured = {}

    class Result:
        result_rows = []

    class Client:
        def query(self, sql, parameters):
            captured.update(sql=sql, parameters=parameters)
            return Result()

        def close(self):
            pass

    monkeypatch.setattr(clickhouse, "connect", lambda: Client())
    clickhouse.raw_log_tail(
        as_of - timedelta(hours=24), as_of, limit=201,
        before_time=as_of + timedelta(seconds=1),
        before_event_id="event-1",
    )

    assert "event_time < {before_time:DateTime64(3)}" in captured["sql"]
    assert "event_id < {before_event_id:String}" in captured["sql"]
    assert "LIMIT 201" in captured["sql"]
    assert captured["parameters"]["before_event_id"] == "event-1"


def test_clickhouse_raw_log_ip_suggestions_normalize_and_bound_results(monkeypatch):
    captured = {}

    class Result:
        result_rows = [("::ffff:34.27.109.32",), ("2001:db8::1",)]

    class Client:
        def query(self, sql, parameters):
            captured.update(sql=sql, parameters=parameters)
            return Result()

        def close(self):
            pass

    monkeypatch.setattr(clickhouse, "connect", lambda: Client())
    as_of = datetime(2026, 9, 28, 12, tzinfo=timezone.utc)
    ips = clickhouse.raw_log_ip_suggestions(
        as_of - timedelta(hours=24), as_of, "34.", limit=30,
        dataset_id="live", status=404,
    )

    assert ips == ["34.27.109.32", "2001:db8::1"]
    assert "FROM http_events FINAL" in captured["sql"]
    assert "GROUP BY src_ip" in captured["sql"]
    assert "LIMIT 12" in captured["sql"]
    assert "{prefix:String}" in captured["sql"]
    assert "status = {status:UInt16}" in captured["sql"]
    assert captured["parameters"]["prefix"] == "34."
    assert captured["parameters"]["status"] == 404
