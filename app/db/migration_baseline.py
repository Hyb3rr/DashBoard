"""Explicit contract for adopting a pre-ledger PostgreSQL schema."""

from __future__ import annotations

from typing import Any


LEGACY_BASELINE_VERSION = 30

# A legacy database is supported only when it contains the complete current
# table set. This is intentionally explicit: migration SQL is not reparsed to
# infer whether an old schema is safe to adopt.
BASELINE_TABLES = frozenset({
    "ai_explain_jobs", "ai_feature_settings", "ai_model_state", "ai_trigger_cursors",
    "ai_trigger_deferred", "alert_outbox", "alerts", "change_consumer_state",
    "country_demand_identity_config", "country_demand_signal", "country_demand_snapshot",
    "data_source_registry", "geo_change_history", "geo_location_observations", "geo_prefixes",
    "geo_resolutions", "geo_source_status", "geo_unit", "industrial_demand_evidence",
    "industrial_demand_snapshot", "intel_source_status", "ip_ai_scores", "ip_change_log",
    "ip_classification_state", "ip_dispositions", "ip_minute_features", "ip_minute_path_seen",
    "ip_observations", "ip_observations_state", "ip_profiles", "log_sources",
    "market_area_opportunity_summary", "market_area_overlap", "market_area_sources",
    "market_areas", "market_catalog", "market_cell_auxiliary_evidence", "market_cell_features",
    "market_city_cell_membership", "market_city_opportunity_summary", "market_city_product_summary",
    "market_country_product_prior", "market_job_state", "market_local_opportunity",
    "market_opportunity_cells", "market_osm_snapshots", "page_classification_rules",
    "privacy_network_history", "privacy_networks", "processed_batches", "product_track",
    "region_profiles", "rfq_intake", "rule_firing_state", "threat_indicators",
})

# Columns introduced or materially changed by non-CREATE migrations. The
# validator checks these explicitly so a table-only adoption cannot skip ALTERs.
BASELINE_COLUMNS: dict[str, dict[str, str]] = {
    "market_local_opportunity": {
        "calibrated_score": "double precision",
        "peer_percentile": "double precision",
        "calibration_method": "text",
        "calibration_version": "text",
        "calibration_status": "text",
    },
    "ai_explain_jobs": {
        "analysis_json": "jsonb",
        "validation_json": "jsonb",
        "provenance_json": "jsonb",
        "validation_status": "text",
        "provider_status": "text",
        "case_packet_json": "jsonb",
    },
    "rfq_intake": {"fx_rate_provider": "text"},
    "geo_unit": {"status": "text"},
    "industrial_demand_evidence": {"geo_unit_id": "text"},
}


def validate_legacy_baseline(conn: Any) -> None:
    """Fail closed unless the database matches the supported pre-ledger baseline."""
    table_rows = conn.execute(
        """SELECT table_name FROM information_schema.tables
           WHERE table_schema = 'public' AND table_name = ANY(%s)""",
        (sorted(BASELINE_TABLES),),
    ).fetchall()
    present_tables = {str(row["table_name"]) for row in table_rows}
    missing_tables = sorted(BASELINE_TABLES - present_tables)
    if missing_tables:
        raise RuntimeError(
            "Legacy database schema does not match supported baseline; "
            f"missing tables: {', '.join(missing_tables)}"
        )

    for table_name, columns in BASELINE_COLUMNS.items():
        rows = conn.execute(
            """SELECT column_name, data_type
               FROM information_schema.columns
              WHERE table_schema = 'public' AND table_name = %s
                AND column_name = ANY(%s)""",
            (table_name, sorted(columns)),
        ).fetchall()
        actual = {str(row["column_name"]): str(row["data_type"]).lower() for row in rows}
        missing = sorted(set(columns) - set(actual))
        if missing:
            raise RuntimeError(
                "Legacy database schema does not match supported baseline; "
                f"{table_name} missing columns: {', '.join(missing)}"
            )
        wrong_types = sorted(
            f"{column} expected {expected}, found {actual[column]}"
            for column, expected in columns.items()
            if actual[column] != expected
        )
        if wrong_types:
            raise RuntimeError(
                "Legacy database schema does not match supported baseline; "
                f"column type mismatch: {', '.join(wrong_types)}"
            )
