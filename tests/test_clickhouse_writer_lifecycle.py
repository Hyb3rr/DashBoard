from app.db import clickhouse


class FakeClient:
    def __init__(self, *, fail=False):
        self.fail = fail
        self.inserts = 0
        self.closed = False

    def insert(self, *_args, **_kwargs):
        if self.fail:
            raise RuntimeError("broken keep-alive")
        self.inserts += 1

    def close(self):
        self.closed = True


def _row():
    return {"event_id": "a" * 64, "src_ip": "203.0.113.1", "path": "/"}


def test_writer_reuses_client_and_recreates_after_failure(monkeypatch):
    clients = []

    def connect():
        client = FakeClient()
        clients.append(client)
        return client

    monkeypatch.setattr(clickhouse, "connect", connect)
    writer = clickhouse.ClickHouseWriter()

    assert writer.insert_events([_row()]) == 1
    assert writer._client is clients[0]
    assert writer._client is not None

    clients[0].fail = True
    try:
        writer.insert_events([_row()])
    except RuntimeError:
        pass
    else:  # pragma: no cover - assertion clarity
        raise AssertionError("broken writer must surface the insert failure")
    assert clients[0].closed is True
    assert writer._client is None

    assert writer.insert_events([_row()]) == 1
    assert len(clients) == 2
    assert clients[1].inserts == 1
    writer.close()
    assert clients[1].closed is True


def test_writer_close_is_idempotent(monkeypatch):
    client = FakeClient()
    monkeypatch.setattr(clickhouse, "connect", lambda: client)
    writer = clickhouse.ClickHouseWriter()
    writer.insert_events([_row()])
    writer.close()
    writer.close()
    assert client.closed is True
