from pathlib import Path


def test_postgres_contract_defines_cold_start_and_page_rules():
    sql = Path("infra/postgres/030_country_demand_traffic_contract.sql").read_text()
    assert "page_classification_rules" in sql
    assert "country_demand_identity_config" in sql
    assert "visitor_identity_go_live_at" in sql
    assert "session_timeout_minutes" in sql


def test_clickhouse_contract_is_append_only_and_unknown_identity_is_explicit():
    sql = Path("infra/clickhouse/002_country_demand_visitor_identity.sql").read_text()
    assert "ADD COLUMN IF NOT EXISTS visitor_id" in sql
    assert "identity_method LowCardinality(String) DEFAULT 'none'" in sql
    assert "cf_bot_score Nullable(UInt8)" in sql
    assert "ALTER TABLE" in sql


def test_clickhouse_insert_preserves_optional_identity_and_cloudflare_fields():
    source = Path("app/db/clickhouse.py").read_text()
    for field in ("visitor_id", "identity_method", "cf_country", "cf_asn", "cf_as_org", "cf_bot_score",
                  "country_source", "cf_js_detection_passed", "session_id", "engagement_seconds",
                  "pageviews", "key_event_count", "geo_confidence", "geo_conflict"):
        assert field in source


def test_country_demand_evidence_migration_is_nullable():
    sql = Path("infra/clickhouse/003_country_demand_evidence.sql").read_text()
    assert "country_source Nullable(String)" in sql
    assert "cf_js_detection_passed Nullable(UInt8)" in sql
    assert "session_id Nullable(String)" in sql
    assert "geo_confidence Nullable(Float64)" in sql
    assert "geo_conflict Nullable(UInt8)" in sql
