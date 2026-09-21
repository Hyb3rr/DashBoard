from pathlib import Path

import pytest

from app.db import clickhouse


def _metadata_rows(overrides=None, extra=()):
    schema = {table: dict(columns) for table, columns in clickhouse._REQUIRED_SCHEMA.items()}
    for key, value in (overrides or {}).items():
        table, column = key
        schema[table].pop(column, None) if value is None else schema[table].__setitem__(column, value)
    return [(table, column, type_) for table, columns in schema.items() for column, type_ in columns.items()] + list(extra)


class _Client:
    def __init__(self, rows):
        self.rows = rows
        self.queries = []
        self.commands = []
        self.closed = False

    def query(self, sql, parameters=None):
        self.queries.append((sql, parameters))
        return type("Result", (), {"result_rows": self.rows})()

    def close(self):
        self.closed = True


def test_verify_schema_accepts_complete_schema_and_extra_columns():
    client = _Client(_metadata_rows(extra=[("http_events", "future_column", "String")]))

    clickhouse.verify_schema(client)

    assert client.commands == []
    assert client.queries


def test_verify_schema_rejects_missing_table():
    rows = [row for row in _metadata_rows() if row[0] != "behavior_events"]

    with pytest.raises(clickhouse.ClickHouseSchemaError, match="Missing ClickHouse table.*behavior_events"):
        clickhouse.verify_schema(_Client(rows))


def test_verify_schema_rejects_missing_column():
    rows = _metadata_rows({("behavior_events", "country_source"): None})

    with pytest.raises(clickhouse.ClickHouseSchemaError, match="behavior_events.country_source is missing"):
        clickhouse.verify_schema(_Client(rows))


def test_verify_schema_rejects_wrong_type():
    rows = _metadata_rows({("behavior_events", "geo_conflict"): "String"})

    with pytest.raises(clickhouse.ClickHouseSchemaError, match=r"geo_conflict expected Nullable\(UInt8\), found String"):
        clickhouse.verify_schema(_Client(rows))


def test_ensure_schema_emits_no_ddl(monkeypatch):
    client = _Client(_metadata_rows())

    monkeypatch.setattr(clickhouse, "connect", lambda: client)
    clickhouse.ensure_schema()

    assert client.commands == []
    assert all(not sql.lstrip().upper().startswith(("CREATE ", "ALTER ", "DROP ")) for sql, _ in client.queries)


def test_behavior_event_evidence_columns_have_a_clickhouse_migration():
    sql = Path("infra/clickhouse/005_behavior_events_evidence.sql").read_text()
    expected = {
        "assigned_country Nullable(String)",
        "country_source Nullable(String)",
        "geo_confidence Nullable(Float64)",
        "geo_conflict Nullable(UInt8)",
        "cf_bot_score Nullable(UInt8)",
        "cf_js_detection_passed Nullable(UInt8)",
        "is_tor Nullable(UInt8)",
        "is_vpn Nullable(UInt8)",
        "is_proxy Nullable(UInt8)",
        "is_hosting Nullable(UInt8)",
        "is_mobile Nullable(UInt8)",
        "is_scanner Nullable(UInt8)",
    }

    assert "ALTER TABLE ipintel.behavior_events" in sql
    assert all(f"ADD COLUMN IF NOT EXISTS {column}" in sql for column in expected)


def test_behavior_event_insert_columns_are_covered_by_base_or_followup_migrations():
    base = Path("infra/clickhouse/004_behavior_events.sql").read_text()
    evidence = Path("infra/clickhouse/005_behavior_events_evidence.sql").read_text()
    runtime = Path("app/db/clickhouse.py").read_text()

    runtime_columns = {
        "event_time", "ingested_at", "event_id", "visitor_id", "session_id",
        "event_name", "path", "engagement_ms", "key_event_name", "payload_hash",
        "assigned_country", "country_source", "geo_confidence", "geo_conflict",
        "cf_bot_score", "cf_js_detection_passed", "is_tor", "is_vpn", "is_proxy",
        "is_hosting", "is_mobile", "is_scanner",
    }
    migration_sql = base + evidence

    assert "client.insert(\"behavior_events\"" in runtime
    assert all(column in migration_sql for column in runtime_columns)
