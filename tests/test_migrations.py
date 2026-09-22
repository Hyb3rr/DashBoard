from pathlib import Path
from datetime import datetime, timedelta, timezone

import pytest

from app.db.migrations import discover
from app.db.migration_baseline import validate_legacy_baseline
from app.db.repositories import should_create_alert, should_create_critical_recurrence


def test_alerts_only_enter_or_raise_severity():
    assert should_create_alert(None, "low")
    assert should_create_alert("good", "medium")
    assert should_create_alert("low", "critical")
    assert not should_create_alert(None, "good")
    assert not should_create_alert("medium", "low")
    assert not should_create_alert("critical", "critical")


def test_critical_recurrence_obeys_thirty_minute_cooldown():
    now = datetime(2026, 9, 5, 12, 30, tzinfo=timezone.utc)
    assert should_create_critical_recurrence("critical", "critical", now - timedelta(minutes=31), now)
    assert not should_create_critical_recurrence("critical", "critical", now - timedelta(minutes=29), now)
    assert not should_create_critical_recurrence("medium", "critical", now - timedelta(minutes=31), now)


def test_postgres_migrations_are_ordered_and_checksumed():
    migrations = discover()

    assert [migration.version for migration in migrations] == list(range(38))
    assert [migration.filename for migration in migrations] == [
        "000_schema_migrations.sql",
        "001_initial.sql",
        "002_market_opportunity.sql",
        "003_market_auxiliary_evidence.sql",
        "004_market_local_opportunity.sql",
        "005_market_local_calibration.sql",
        "006_market_overlap.sql",
        "007_market_area_summary.sql",
        "008_market_city_membership.sql",
        "009_market_city_summary.sql",
        "010_ai_explain_jobs.sql",
        "011_ai_explain_job_results.sql",
        "012_ai_explain_job_packets.sql",
            "013_ai_trigger_state.sql",
            "014_ai_trigger_backlog.sql",
        "015_classification_tiers.sql",
        "016_alerts.sql",
        "017_alert_inventory.sql",
        "018_alert_inventory_timestamps.sql",
        "019_ai_auto_explain_settings.sql",
        "020_market_potential_foundation.sql",
        "021_market_contract_alignment.sql",
        "022_market_sales_intake.sql",
        "023_market_sales_fx_audit.sql",
        "024_market_potential_bootstrap.sql",
        "025_geo_unit_candidate_status.sql",
        "026_market_summary_composite_key.sql",
        "027_industrial_demand_evidence.sql",
        "028_industrial_demand_source_geo_ids.sql",
        "029_country_demand_signals.sql",
        "030_country_demand_traffic_contract.sql",
        "031_alert_outbox_pending_retry_index.sql",
        "032_city_overall_opportunity.sql",
        "033_realtime_change_notify.sql",
        "034_prune_orphan_alert_state.sql",
        "035_align_inventory_alert_timestamps.sql",
        "036_city_overall_runtime_read_grants.sql",
        "037_enrichment_requests.sql",
        ]
    assert all(len(migration.checksum_sha256) == 64 for migration in migrations)


def test_migrations_extract_table_contracts():
    migrations = {migration.version: migration for migration in discover()}

    assert migrations[0].tables == {"schema_migrations"}
    assert "ip_minute_features" in migrations[1].tables
    assert "market_opportunity_cells" in migrations[2].tables
    assert "market_city_opportunity_summary" in migrations[9].tables
    assert "ai_explain_jobs" in migrations[10].tables
    assert migrations[11].tables == set()
    assert migrations[12].tables == set()
    assert migrations[13].tables == {"ai_trigger_cursors"}
    assert migrations[14].tables == {"ai_trigger_deferred"}
    assert migrations[16].tables == {"alerts"}
    assert migrations[17].tables == set()
    assert migrations[18].tables == set()
    assert migrations[19].tables == {"ai_feature_settings"}
    assert migrations[20].tables == {
        "geo_unit", "product_track", "data_source_registry", "market_city_product_summary"
    }
    assert migrations[21].tables == {"market_city_product_summary"}
    assert migrations[22].tables == {"rfq_intake"}
    assert migrations[23].tables == set()
    assert migrations[24].tables == {"market_country_product_prior"}
    assert migrations[25].tables == set()
    assert migrations[26].tables == set()
    assert migrations[27].tables == {"industrial_demand_snapshot", "industrial_demand_evidence"}
    assert migrations[28].tables == set()
    assert migrations[31].tables == set()
    assert "DELETE FROM alerts" in migrations[34].sql
    assert "DELETE FROM ip_classification_state" in migrations[34].sql
    assert "created_at = cs.updated_at" in migrations[35].sql


def test_alert_outbox_pending_retry_migration_matches_worker_query():
    migration = {migration.version: migration for migration in discover()}[31]
    assert "CREATE INDEX IF NOT EXISTS idx_alert_outbox_pending_retry" in migration.sql
    assert "ON alert_outbox (next_retry_at ASC, id ASC)" in migration.sql
    assert "WHERE status = 'pending'" in migration.sql


class _BaselineConnection:
    def __init__(self, tables, columns):
        self.tables = tables
        self.columns = columns

    def execute(self, sql, params=()):
        if "information_schema.tables" in sql:
            return _Rows([{"table_name": table} for table in self.tables])
        table_name, requested = params
        return _Rows([
            {"column_name": column, "data_type": data_type}
            for column, data_type in self.columns.get(table_name, {}).items()
            if column in requested
        ])


class _Rows:
    def __init__(self, rows):
        self.rows = rows

    def fetchall(self):
        return self.rows


def test_legacy_baseline_rejects_existing_table_with_missing_alter_column():
    from app.db.migration_baseline import BASELINE_COLUMNS, BASELINE_TABLES

    columns = {table: dict(required) for table, required in BASELINE_COLUMNS.items()}
    del columns["market_local_opportunity"]["calibrated_score"]

    try:
        validate_legacy_baseline(_BaselineConnection(BASELINE_TABLES, columns))
    except RuntimeError as exc:
        assert "market_local_opportunity" in str(exc)
        assert "calibrated_score" in str(exc)
    else:
        raise AssertionError("incomplete legacy baseline was accepted")


def test_legacy_baseline_accepts_complete_explicit_contract():
    from app.db.migration_baseline import BASELINE_COLUMNS, BASELINE_TABLES

    columns = {table: dict(required) for table, required in BASELINE_COLUMNS.items()}
    validate_legacy_baseline(_BaselineConnection(BASELINE_TABLES, columns))


def test_init_storage_uses_migration_runner():
    source = Path("scripts/ops/init_storage.py").read_text(encoding="utf-8")

    assert "migrations.apply_after_base_schema" in source
    assert "migration_name" not in source


def test_dev_launcher_applies_storage_migrations_before_app_start():
    source = Path("scripts/dev_run.sh").read_text(encoding="utf-8")
    assert 'source "$ROOT_DIR/.env"' in source
    assert source.index('source "$ROOT_DIR/.env"') < source.index("init_storage.py")
    assert ".venv/bin/python scripts/ops/init_storage.py" in source
    assert source.index("clickhouse_healthy()") < source.index("init_storage.py")
    assert source.index("init_storage.py") < source.index("start_local_ai")
    assert "run_explain_worker" in source
    assert "start_data_scheduler" in source
    assert "DATA_SCHEDULER_INTERVAL_SECONDS" in source
    assert 'wait "$UVICORN_PID"' in source


def test_clickhouse_migration_runner_is_ordered_and_checksum_checked(tmp_path):
    from scripts.ops import clickhouse_migrations

    (tmp_path / "001_base.sql").write_text("CREATE TABLE IF NOT EXISTS ipintel.base (id UInt8)")
    (tmp_path / "002_fix.sql").write_text("ALTER TABLE ipintel.base ADD COLUMN IF NOT EXISTS value UInt8")
    assert [item[0] for item in clickhouse_migrations.discover(tmp_path)] == [1, 2]
    assert clickhouse_migrations.statements("ALTER TABLE a; ALTER TABLE b;") == [
        "ALTER TABLE a", "ALTER TABLE b",
    ]

    class Result:
        result_rows = []

    class Client:
        def __init__(self):
            self.commands = []

        def command(self, sql, **kwargs):
            self.commands.append((sql, kwargs))

        def query(self, _sql):
            return Result()

        def insert(self, _table, _rows, column_names=None):
            self.commands.append(("INSERT", {"column_names": column_names}))

    client = Client()
    clickhouse_migrations.apply(client, directory=tmp_path)
    assert [sql for sql, _kwargs in client.commands[1::2]] == [
        "CREATE TABLE IF NOT EXISTS ipintel.base (id UInt8)",
        "ALTER TABLE ipintel.base ADD COLUMN IF NOT EXISTS value UInt8",
    ]


def test_clickhouse_runner_bootstraps_database_before_schema(monkeypatch):
    source = Path("scripts/ops/clickhouse_migrations.py").read_text(encoding="utf-8")
    launcher = Path("scripts/dev_run.sh").read_text(encoding="utf-8")
    assert 'connect(database="default")' in source
    assert "CREATE DATABASE IF NOT EXISTS" in source
    assert 'pg_ctl -D "$POSTGRES_DATA_DIR" status' in launcher
    assert 'Removing stale PostgreSQL PID file' in launcher


def test_clickhouse_runner_accepts_fixed_string_checksum_bytes(tmp_path):
    from scripts.ops import clickhouse_migrations

    migration = tmp_path / "001_base.sql"
    migration.write_text("CREATE TABLE IF NOT EXISTS ipintel.base (id UInt8)")
    version, filename, checksum, _sql = clickhouse_migrations.discover(tmp_path)[0]

    class Result:
        result_rows = [(version, filename.encode(), checksum.encode())]

    class Client:
        def __init__(self):
            self.applied_sql = []

        def command(self, sql, **_kwargs):
            self.applied_sql.append(sql)

        def query(self, _sql):
            return Result()

        def insert(self, *_args, **_kwargs):
            raise AssertionError("already applied migration was recorded again")

    client = Client()
    clickhouse_migrations.apply(client, directory=tmp_path)
    assert len(client.applied_sql) == 1


def test_clickhouse_runner_rejects_genuine_checksum_change(tmp_path):
    from scripts.ops import clickhouse_migrations

    migration = tmp_path / "001_base.sql"
    migration.write_text("CREATE TABLE IF NOT EXISTS ipintel.base (id UInt8)")

    class Result:
        result_rows = [(1, b"001_base.sql", b"0" * 64)]

    class Client:
        def command(self, _sql, **_kwargs):
            pass

        def query(self, _sql):
            return Result()

    with pytest.raises(RuntimeError, match="checksum mismatch"):
        clickhouse_migrations.apply(Client(), directory=tmp_path)


def test_clickhouse_evidence_repair_migration_covers_confirmed_bool_drift():
    sql = Path("infra/clickhouse/007_normalize_evidence_column_types.sql").read_text()
    expected = {
        "cf_js_detection_passed", "geo_conflict", "is_hosting", "is_mobile",
        "is_proxy", "is_scanner", "is_tor", "is_vpn",
    }
    assert {
        line.split()[2]
        for line in sql.splitlines()
        if line.strip().startswith("MODIFY COLUMN")
    } == expected
    assert sql.count("Nullable(UInt8)") == len(expected)


def test_clickhouse_retention_repair_removes_unverified_behavior_ttl():
    sql = Path("infra/clickhouse/009_remove_unverified_behavior_ttl.sql").read_text()
    assert "ALTER TABLE ipintel.behavior_events REMOVE TTL" in sql
    assert "ALTER TABLE ipintel.http_events" not in sql
