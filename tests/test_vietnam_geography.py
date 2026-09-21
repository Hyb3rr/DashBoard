import json
from pathlib import Path

import pytest

from app.core.vietnam_geography import PROVINCES, aggregation_policy, canonical_province, crosswalk_legacy_code


ROOT = Path(__file__).parents[1]


def test_canonical_catalog_has_34_unique_units_and_vietnam_scope():
    schema = json.loads((ROOT / "schemas/vietnam_provinces_2025.json").read_text())
    assert schema["country_code"] == "VN"
    assert len(PROVINCES) == 34
    assert len({item["code"] for item in PROVINCES}) == 34
    assert canonical_province("79")["name"] == "Hồ Chí Minh"


def test_crosswalk_covers_all_63_legacy_codes():
    crosswalk = json.loads((ROOT / "schemas/vietnam_province_crosswalk.json").read_text())
    entries = crosswalk["entries"]
    assert len(entries) == 63
    assert len({item["old_code"] for item in entries}) == 63
    assert {item["new_code"] for item in entries} <= {item["code"] for item in PROVINCES}
    assert crosswalk_legacy_code("79")["new_code"] == "79"


def test_historical_rates_indexes_and_growth_are_not_silently_added():
    assert aggregation_policy("count", "merged") == "additive_only"
    assert aggregation_policy("amount", "merged") == "additive_only"
    assert aggregation_policy("index", "merged") == "requires_methodology"
    assert aggregation_policy("growth", "merged") == "requires_methodology"
    assert aggregation_policy("share", "merged") == "requires_methodology"


def test_unknown_codes_fail_closed():
    with pytest.raises(ValueError):
        canonical_province("99")
    with pytest.raises(ValueError):
        crosswalk_legacy_code("99")
