import inspect
from pathlib import Path

import pytest

from app.core.market_catalog import NON_PRIMARY_ECONOMIES, PRIMARY_UN_MEMBERS, catalog_rows
from app.db import market_repository


class _Result:
    def __init__(self, row=None, rows=None):
        self.row = row
        self.rows = rows or []

    def fetchone(self):
        return self.row

    def fetchall(self):
        return self.rows


class _Connection:
    def __init__(self):
        self.executed = []
        self.batches = []

    def execute(self, sql, params=()):
        self.executed.append((sql, params))
        return _Result(row={"job_key": "osm:DE", "status": "done"})

    def executemany(self, sql, values):
        self.batches.append((sql, list(values)))

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Transaction:
    def __init__(self, connection):
        self.connection = connection

    def __enter__(self):
        return self.connection

    def __exit__(self, *exc):
        return False


def _repo(monkeypatch):
    connection = _Connection()
    monkeypatch.setattr(market_repository, "transaction", lambda: _Transaction(connection))
    return market_repository.MarketRepository(), connection


def test_canonical_catalog_has_exactly_193_primary_and_24_non_primary():
    assert len(PRIMARY_UN_MEMBERS) == 193
    assert len(NON_PRIMARY_ECONOMIES) == 24
    rows = catalog_rows()
    assert len(rows) == 217
    assert sum(item["primary_market"] for item in rows) == 193
    assert {item["country_code"] for item in rows if not item["primary_market"]} == {
        item[0] for item in NON_PRIMARY_ECONOMIES
    }


def test_non_primary_examples_are_not_promoted():
    rows = {item["country_code"]: item for item in catalog_rows()}
    assert rows["HK"]["primary_market"] is False
    assert rows["PR"]["primary_market"] is False
    assert rows["PS"]["primary_market"] is False
    assert rows["XK"]["primary_market"] is False
    assert rows["PS"]["un_member"] is False


def test_catalog_upsert_is_batch_and_rejects_duplicate_codes(monkeypatch):
    repo, connection = _repo(monkeypatch)
    assert repo.upsert_catalog(catalog_rows()[:2]) == 2
    assert len(connection.batches) == 1
    with pytest.raises(ValueError):
        repo.upsert_catalog([catalog_rows()[0], catalog_rows()[0]])


def test_area_types_parent_and_source_upserts(monkeypatch):
    repo, connection = _repo(monkeypatch)
    areas = [
        {"area_id": "DE:ADM1:BY", "country_code": "DE", "name": "Bavaria",
         "area_type": "administrative_area", "admin_level": 1, "source": "geoboundaries", "source_id": "BY"},
        {"area_id": "DE:CITY:MUC", "country_code": "DE", "name": "Munich",
         "area_type": "city", "parent_area_id": "DE:ADM1:BY", "source": "ghsl", "source_id": "MUC"},
        {"area_id": "DE:CLUSTER:1", "country_code": "DE", "name": "Cluster 1",
         "area_type": "industrial_cluster", "parent_area_id": "DE:ADM1:BY", "source": "industrial_land", "source_id": "1"},
    ]
    assert repo.upsert_areas(areas) == 3
    assert repo.upsert_area_sources([{"area_id": "DE:CITY:MUC", "source_name": "ghsl", "source_object_id": "MUC", "source_confidence": 90}]) == 1
    assert len(connection.batches) == 2
    with pytest.raises(ValueError):
        repo.upsert_areas([{**areas[0], "area_type": "country"}])


def test_job_state_lifecycle_and_error_are_persisted(monkeypatch):
    repo, connection = _repo(monkeypatch)
    for status in ("pending", "downloading", "processing", "validating", "done"):
        result = repo.upsert_job_state({"job_key": "osm:DE", "source": "osm", "status": status, "current_step": status})
        assert result["status"] == "done"  # fake RETURNING row proves write path is used
    repo.upsert_job_state({"job_key": "osm:DE", "source": "osm", "status": "failed", "last_error": "network"})
    assert any("last_error" in sql for sql, _ in connection.executed)


def test_init_storage_remains_explicit_and_lifespan_does_not_call_ddl():
    source = inspect.getsource(__import__("app.main", fromlist=["lifespan"]).lifespan)
    assert "ensure_schema" not in source
    migration = Path(__file__).parents[1] / "infra" / "postgres" / "002_market_opportunity.sql"
    assert migration.exists()


def test_auxiliary_evidence_upsert_is_batch_and_idempotent(monkeypatch):
    repo, connection = _repo(monkeypatch)
    item = {
        "snapshot_id": "osm:DE:hash:phase:r7", "country_code": "DE", "h3_cell_id": "8928308280fffff",
        "h3_resolution": 7, "track": "woodworking", "source": "osm_auxiliary",
        "source_version": "phase5a-v1", "source_hash": "b" * 64,
        "industrial_land_count": 3, "motorway_count": 2, "access_observation_count": 5,
    }
    assert repo.upsert_auxiliary_evidence([item]) == 1
    assert len(connection.batches) == 1
    sql, values = connection.batches[0]
    assert "market_cell_auxiliary_evidence" in sql
    assert values[0][8] == 3
    assert values[0][15] == "observed"


def test_auxiliary_migration_is_explicit_followup():
    migration = Path(__file__).parents[1] / "infra" / "postgres" / "003_market_auxiliary_evidence.sql"
    assert migration.exists()
    assert "CREATE TABLE IF NOT EXISTS market_cell_auxiliary_evidence" in migration.read_text()


def test_local_opportunity_upsert_preserves_missing_evidence_as_null(monkeypatch):
    repo, connection = _repo(monkeypatch)
    item = {
        "snapshot_id": "osm:DE:hash:phase:r7", "country_code": "DE", "h3_cell_id": "8928308280fffff",
        "h3_resolution": 7, "track": "metal_fabrication", "raw_local_score": None,
        "evidence_status": "insufficient_local_evidence", "missing_reason": "insufficient_local_evidence",
        "coverage_fields": {"osm_confidence": "low"}, "model_version": "phase6a-v1",
    }
    assert repo.upsert_local_opportunity([item]) == 1
    sql, values = connection.batches[-1]
    assert "market_local_opportunity" in sql
    assert values[0][6] is None
    assert values[0][7] == "insufficient_local_evidence"


def test_local_opportunity_migration_is_explicit_followup():
    migration = Path(__file__).parents[1] / "infra" / "postgres" / "004_market_local_opportunity.sql"
    assert migration.exists()
    assert "raw_local_score DOUBLE PRECISION" in migration.read_text()


def test_local_calibration_migration_is_explicit_followup():
    migration = Path(__file__).parents[1] / "infra" / "postgres" / "005_market_local_calibration.sql"
    assert migration.exists()
    text = migration.read_text()
    assert "calibrated_score DOUBLE PRECISION" in text
    assert "peer_percentile DOUBLE PRECISION" in text
    assert "calibration_status TEXT NOT NULL DEFAULT 'not_selected'" in text


def test_overlap_migration_is_explicit_followup():
    migration = Path(__file__).parents[1] / "infra" / "postgres" / "006_market_overlap.sql"
    assert migration.exists()
    text = migration.read_text()
    assert "CREATE TABLE IF NOT EXISTS market_area_overlap" in text
    assert "overlap_a_to_b DOUBLE PRECISION" in text
    assert "remaining_opportunity_b DOUBLE PRECISION" in text
    assert "area_id_a <> area_id_b" in text


def test_area_summary_migration_is_explicit_followup():
    migration = Path(__file__).parents[1] / "infra/postgres/007_market_area_summary.sql"
    assert migration.exists()
    text = migration.read_text()
    assert "CREATE TABLE IF NOT EXISTS market_area_opportunity_summary" in text
    assert "area_raw_score DOUBLE PRECISION" in text
    assert "scored_cells <= total_cells" in text


def test_area_summary_upsert_is_batch_and_preserves_missing_score(monkeypatch):
    repo, connection = _repo(monkeypatch)
    item = {
        "snapshot_id": "osm:DE:hash:phase:r7", "country_code": "DE", "h3_resolution": 7,
        "area_id": "DE:ADM1:BY", "track": "woodworking", "total_cells": 3,
        "scored_cells": 0, "evidence_coverage": 0, "area_raw_score": None,
        "evidence_status": "insufficient_local_evidence", "missing_reason": "insufficient_local_evidence",
        "model_version": "phase6a-area-v1",
    }
    assert repo.upsert_area_opportunity_summaries([item]) == 1
    sql, values = connection.batches[-1]
    assert "market_area_opportunity_summary" in sql
    assert values[0][8] is None
    assert values[0][11] == "insufficient_local_evidence"


def test_city_membership_upsert_is_batch_and_preserves_geometry_provenance(monkeypatch):
    repo, connection = _repo(monkeypatch)
    item = {
        "snapshot_id": "osm:DE:hash:phase:r7", "country_code": "DE", "city_id": "DE:CITY:1",
        "h3_cell_id": "8928308280fffff", "h3_resolution": 7, "intersection_area": 10.0,
        "membership_fraction": .25, "geometry_source": "ghsl", "geometry_version": "r2024a",
        "model_version": "lc2a-v1",
    }
    assert repo.upsert_city_cell_memberships([item]) == 1
    sql, values = connection.batches[-1]
    assert "market_city_cell_membership" in sql
    assert values[0][6] == .25
    assert values[0][8] == "r2024a"


def test_city_summary_upsert_preserves_weighted_fields(monkeypatch):
    repo, connection = _repo(monkeypatch)
    item = {"snapshot_id": "s", "country_code": "DE", "city_id": "DE:CITY:1", "track": "woodworking",
            "total_cells": 2, "scored_cells": 1, "membership_weight": .75, "scored_membership_weight": .5,
            "evidence_coverage": 2/3, "city_raw_score": 30, "evidence_status": "scored",
            "geometry_source": "ghsl_ucdb_r2024a", "model_version": "lc2b-v1"}
    assert repo.upsert_city_opportunity_summaries([item]) == 1
    sql, values = connection.batches[-1]
    assert "market_city_opportunity_summary" in sql
    assert values[0][6] == .75
    assert values[0][9] == 30
