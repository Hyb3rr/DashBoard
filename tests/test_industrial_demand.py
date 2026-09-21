import json
from pathlib import Path

import pytest

from app.core.industrial_demand import (
    build_profiles,
    coverage,
    evidence_id,
    load_matrix,
    normalize_evidence,
    validate_matrix,
)


MATRIX = Path("schemas/product_industry_matrix.json")


def _evidence(**changes):
    row = {
        "product_id": "panel_saw",
        "source_id": "osm_overpass",
        "source_geo_scope": "geo_unit",
        "geo_unit_id": "VN:ADM1:BD",
        "observed_value": 0,
        "unit": "observed_entities",
        "observed_period": "2026-Q3",
        "collected_at": "2026-09-09T00:00:00Z",
        "mapping_version": "market-demand-v2",
        "limitations": ["partial OSM coverage"],
    }
    row.update(changes)
    return row


def test_matrix_has_fourteen_sellable_products_and_proxy_is_evidence_only():
    matrix = load_matrix(MATRIX)
    assert len(matrix["products"]) == 14
    assert "furniture_export_proxy" not in {item["product_id"] for item in matrix["products"]}
    assert matrix["industry_proxy"]["role"] == "evidence_only"


def test_matrix_rejects_score_contract_or_missing_mapping_metadata():
    matrix = json.loads(MATRIX.read_text())
    matrix["scoring"] = "weighted_score"
    with pytest.raises(ValueError, match="evidence-only"):
        validate_matrix(matrix)
    matrix = json.loads(MATRIX.read_text())
    del matrix["products"][0]["rationale"]
    with pytest.raises(ValueError, match="missing"):
        validate_matrix(matrix)


def test_country_evidence_cannot_be_relabelled_as_province_evidence():
    with pytest.raises(ValueError, match="country evidence"):
        normalize_evidence(_evidence(source_geo_scope="country"))


def test_missing_value_stays_missing_but_explicit_zero_is_observed():
    zero = normalize_evidence(_evidence(observed_value=0))
    missing = normalize_evidence(_evidence(observed_value=None))
    assert coverage([zero, missing]) == {"observed": 1, "total": 2, "ratio": 0.5, "missing": 1}


def test_evidence_identity_is_deterministic_and_changes_with_content():
    first = normalize_evidence(_evidence())
    second = normalize_evidence(_evidence())
    changed = normalize_evidence(_evidence(observed_value=2))
    assert first["evidence_id"] == second["evidence_id"] == evidence_id(first)
    assert first["evidence_id"] != changed["evidence_id"]


def test_profiles_include_products_with_no_evidence_and_sort_products():
    profiles = build_profiles(load_matrix(MATRIX), [_evidence()])
    assert len(profiles) == 14
    assert [row["product_id"] for row in profiles] == sorted(row["product_id"] for row in profiles)
    assert next(row for row in profiles if row["product_id"] == "panel_saw")["coverage"]["ratio"] == 1.0
    assert next(row for row in profiles if row["product_id"] == "cnc_router")["coverage"]["ratio"] == 0.0


def test_profiles_reject_unknown_products():
    with pytest.raises(ValueError, match="unknown sellable product"):
        build_profiles(load_matrix(MATRIX), [_evidence(product_id="not-a-product")])
