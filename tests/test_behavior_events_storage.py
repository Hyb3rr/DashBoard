from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Lock

from app.core.behavior_events import normalize_behavior_event
from app.db import clickhouse


def event(event_id="evt-1", **overrides):
    value = {"event_id": event_id, "timestamp": datetime.now(timezone.utc).isoformat(), "visitor_id": "vis-1", "session_id": "ses-1", "event_name": "page_view", "path": "/pricing", "engagement_ms": None, "key_event_name": None}
    value.update(overrides)
    return normalize_behavior_event(value)


def test_same_event_id_same_payload_is_duplicate(monkeypatch):
    from app.db import clickhouse
    existing = event()
    class Client:
        def query(self, *_args, **_kwargs):
            return type("Result", (), {"result_rows": [["evt-1", existing["payload_hash"]]]})()
        def close(self): pass
    monkeypatch.setattr(clickhouse, "connect", lambda: Client())
    result = clickhouse.insert_behavior_events([existing])
    assert result["accepted"] == 0
    assert result["duplicates"] == 1


def test_same_event_id_different_payload_is_conflict(monkeypatch):
    from app.db import clickhouse
    first = event()
    class Client:
        def query(self, *_args, **_kwargs):
            return type("Result", (), {"result_rows": [["evt-1", first["payload_hash"]]]})()
        def close(self): pass
    monkeypatch.setattr(clickhouse, "connect", lambda: Client())
    result = clickhouse.insert_behavior_events([event(path="/contact")])
    assert result["accepted"] == 0
    assert result["conflicts"] == 1
    assert result["errors"][0]["code"] == "EVENT_ID_CONFLICT"


def test_different_event_ids_are_inserted_together(monkeypatch):
    from app.db import clickhouse
    inserted = []
    class Client:
        def query(self, *_args, **_kwargs):
            return type("Result", (), {"result_rows": []})()
        def insert(self, _table, values, **_kwargs):
            inserted.extend(values)
        def close(self): pass
    monkeypatch.setattr(clickhouse, "connect", lambda: Client())
    result = clickhouse.insert_behavior_events([event("evt-1"), event("evt-2")])
    assert result["accepted"] == 2
    assert len(inserted) == 2


def test_same_batch_same_payload_is_inserted_once(monkeypatch):
    first = event()
    inserted = []

    class Client:
        def query(self, *_args, **_kwargs):
            return type("Result", (), {"result_rows": []})()
        def insert(self, _table, values, **_kwargs):
            inserted.extend(values)
        def close(self): pass

    monkeypatch.setattr(clickhouse, "connect", lambda: Client())
    result = clickhouse.insert_behavior_events([first, first.copy()])

    assert result["accepted"] == 1
    assert result["duplicates"] == 1
    assert len(inserted) == 1


def test_same_batch_different_payload_is_conflict(monkeypatch):
    inserted = []

    class Client:
        def query(self, *_args, **_kwargs):
            return type("Result", (), {"result_rows": []})()
        def insert(self, _table, values, **_kwargs):
            inserted.extend(values)
        def close(self): pass

    monkeypatch.setattr(clickhouse, "connect", lambda: Client())
    result = clickhouse.insert_behavior_events([event(), event(path="/contact")])

    assert result["accepted"] == 1
    assert result["conflicts"] == 1
    assert result["errors"] == [{"index": 1, "code": "EVENT_ID_CONFLICT"}]
    assert len(inserted) == 1


def test_concurrent_same_id_can_reach_two_physical_insert_attempts(monkeypatch):
    first = event()
    checked = Barrier(2)
    inserted = []
    lock = Lock()

    class Client:
        def query(self, *_args, **_kwargs):
            checked.wait(timeout=1)
            return type("Result", (), {"result_rows": []})()
        def insert(self, _table, values, **_kwargs):
            with lock:
                inserted.extend(values)
        def close(self): pass

    monkeypatch.setattr(clickhouse, "connect", lambda: Client())
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: clickhouse.insert_behavior_events([first.copy()]), range(2)))

    assert [result["accepted"] for result in results] == [1, 1]
    assert len(inserted) == 2


def test_concurrent_same_id_different_payload_can_both_insert(monkeypatch):
    first, second = event(), event(path="/contact")
    checked = Barrier(2)
    inserted = []
    lock = Lock()

    class Client:
        def query(self, *_args, **_kwargs):
            checked.wait(timeout=1)
            return type("Result", (), {"result_rows": []})()
        def insert(self, _table, values, **_kwargs):
            with lock:
                inserted.extend(values)
        def close(self): pass

    monkeypatch.setattr(clickhouse, "connect", lambda: Client())
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(clickhouse.insert_behavior_events, ([first], [second])))

    assert [result["accepted"] for result in results] == [1, 1]
    assert len(inserted) == 2
