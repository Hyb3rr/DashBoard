from pathlib import Path
from datetime import datetime, timedelta, timezone

from app.db.migrations import discover
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

    assert [migration.version for migration in migrations] == list(range(20))
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
    assert "wait \"$UVICORN_PID\"" in source
