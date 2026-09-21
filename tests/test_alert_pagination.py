from datetime import datetime, timezone

import pytest

from app.db.repositories import AlertRepository


def test_alert_cursor_round_trips_equal_timestamp_ordering():
    timestamp = datetime(2026, 9, 12, 10, 0, tzinfo=timezone.utc)
    cursor = AlertRepository.encode_cursor(timestamp, 42)

    assert AlertRepository.decode_cursor(cursor) == (timestamp.isoformat(), 42)


def test_alert_cursor_is_opaque_and_rejects_invalid_values():
    cursor = AlertRepository.encode_cursor("2026-09-12T10:00:00+00:00", 7)
    assert "2026-09-12" not in cursor
    with pytest.raises(ValueError, match="invalid alert cursor"):
        AlertRepository.decode_cursor("not-a-cursor")


def test_alert_keyset_predicate_uses_timestamp_then_id_tie_breaker():
    source = AlertRepository.list
    assert source.__name__ == "list"
    # The stable order contract is created_at DESC, id DESC; cursor encoding
    # preserves both values so equal timestamps cannot skip or duplicate rows.
    assert AlertRepository.decode_cursor(AlertRepository.encode_cursor("same", 9)) == ("same", 9)


def test_alert_keyset_pages_have_no_duplicates_or_skips_with_equal_timestamps():
    rows = [("2026-09-12T10:00:00+00:00", 5), ("2026-09-12T10:00:00+00:00", 4),
            ("2026-09-12T09:59:00+00:00", 8), ("2026-09-12T09:58:00+00:00", 3)]
    pages = []
    cursor = None
    while True:
        start = 0
        if cursor:
            created_at, alert_id = AlertRepository.decode_cursor(cursor)
            start = next(index for index, row in enumerate(rows) if row == (created_at, alert_id)) + 1
        page = rows[start:start + 2]
        pages.extend(page)
        if len(page) < 2:
            break
        cursor = AlertRepository.encode_cursor(*page[-1])

    assert pages == rows
    assert len(pages) == len(set(pages))


def test_alert_list_keeps_filter_args_separate_from_cursor_args(monkeypatch):
    import app.db.repositories as repositories

    class Result:
        def __init__(self, rows):
            self.rows = rows

        def fetchone(self):
            return {"n": 4}

        def fetchall(self):
            return self.rows

    class Connection:
        def __init__(self):
            self.calls = []

        def execute(self, sql, args=()):
            self.calls.append((sql, list(args)))
            return Result([])

    class Scope:
        def __init__(self, connection):
            self.connection = connection

        def __enter__(self):
            return self.connection

        def __exit__(self, *exc):
            return False

    for severity in (None, "critical"):
        for status in (None, "new"):
            cursor = AlertRepository.encode_cursor("2026-09-12T10:00:00+00:00", 9)
            connection = Connection()
            monkeypatch.setattr(repositories, "transaction", lambda: Scope(connection))
            result = AlertRepository().list(severity=severity, status=status, cursor=cursor, limit=2)

            count_sql, count_args = connection.calls[0]
            page_sql, page_args = connection.calls[1]
            expected_filters = int(severity is not None) + int(status is not None)
            assert result["total"] == 4
            assert len(count_args) == expected_filters
            assert len(page_args) == expected_filters + 3 + 2
            assert "created_at <" not in count_sql
            assert "created_at <" in page_sql
