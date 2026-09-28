import json

import pytest

from scripts.market.vietnam_current_indicators import refresh, seed_snapshot


def test_nq262_snapshot_covers_current_34_units_without_turning_dashes_into_zero():
    payload = seed_snapshot(retrieved_at="2026-09-10T00:00:00+00:00")
    assert payload["coverage"] == {
        "source_observations": 34,
        "province_rows": 34,
        "iip_numeric": 34,
        "fdi_numeric": 29,
        "fdi_reported_without_numeric": 5,
        "fdi_missing": 0,
    }
    by_name = {row["province_name"]: row for row in payload["records"]}
    assert by_name["Hà Nội"]["iip_yoy_pct"] == 8.9
    assert by_name["Lào Cai"]["fdi_registered_period_usd_million"] == -24.56
    assert by_name["Sơn La"]["fdi_status"] == "reported_no_numeric_value"
    assert by_name["Sơn La"]["fdi_registered_period_usd_million"] is None


def test_decimal_comma_and_current_geography_are_preserved():
    payload = seed_snapshot(retrieved_at="2026-09-10T00:00:00+00:00")
    assert {row["geo_unit_id"] for row in payload["records"]} == {
        "01", "04", "08", "11", "12", "14", "15", "19", "20", "22", "24", "25", "31", "33", "37", "38", "40", "42", "44", "46", "48", "51", "52", "56", "66", "68", "75", "79", "80", "82", "86", "91", "92", "96",
    }


def test_refresh_seed_uses_shared_snapshot_contract(tmp_path):
    output = tmp_path / "nested" / "province-indicators.json"

    payload = refresh(None, output)

    stored = json.loads(output.read_text(encoding="utf-8"))
    assert stored["coverage"] == payload["coverage"]
    assert stored["records"] == payload["records"]
    assert stored["source"]["source_basis"].startswith("Checked transcription")


def test_refresh_rejects_incomplete_source_without_overwriting_snapshot(tmp_path):
    source = tmp_path / "partial.html"
    source.write_text("<table><tr><td>not a province record</td></tr></table>", encoding="utf-8")
    output = tmp_path / "province-indicators.json"
    output.write_text("previous snapshot", encoding="utf-8")

    with pytest.raises(ValueError, match="snapshot was not published"):
        refresh(source, output)

    assert output.read_text(encoding="utf-8") == "previous snapshot"
