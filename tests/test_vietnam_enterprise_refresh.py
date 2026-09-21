from scripts.market.vietnam_enterprise_refresh import collect_snapshot


def test_enterprise_snapshot_uses_active_prefix_totals_and_preserves_raw_codes():
    def fetch(url):
        if url.endswith("/provinces"):
            return {"items": [{"code": "VN-HN", "name_vi": "Hà Nội", "slug": "ha-noi"}]}
        if "industry=C16" in url:
            return {"total": 4}
        if "industry=C31" in url:
            return {"total": 6}
        if "industry=C24" in url:
            return {"total": 2}
        if "industry=C25" in url:
            return {"total": 3}
        if "industry=C28" in url:
            return {"total": 5}
        raise AssertionError(url)

    snapshot = collect_snapshot(fetch=fetch, province_limit=1, delay_seconds=0, retrieved_at="2026-09-10T00:00:00Z")
    row = snapshot["records"][0]
    assert row["geo_unit_id"] == "01"
    assert row["tracks"]["woodworking"]["value"] == 10
    assert row["tracks"]["metalworking"]["value"] == 10
    assert row["tracks"]["woodworking"]["source_name"] == "Doanhnghiep.vn public company API"
    assert row["tracks"]["woodworking"]["reference_period"] == "source-current"
    assert [item["api_filter_code"] for item in row["tracks"]["woodworking"]["components"]] == ["C16", "C31"]
    assert snapshot["complete"] is False


def test_failed_prefix_does_not_become_zero():
    def fetch(url):
        if url.endswith("/provinces"):
            return {"items": [{"code": "VN-HN", "name_vi": "Hà Nội", "slug": "ha-noi"}]}
        if "industry=C16" in url:
            return {"total": 0}
        if "industry=C31" in url:
            raise RuntimeError("rate limit")
        return {"total": 1}

    row = collect_snapshot(fetch=fetch, province_limit=1, delay_seconds=0)["records"][0]
    assert row["tracks"]["woodworking"]["value"] is None
    assert row["tracks"]["woodworking"]["components"][0]["value"] == 0
    assert row["tracks"]["woodworking"]["components"][1]["value"] is None


def test_missing_current_province_is_unknown_not_zero():
    snapshot = collect_snapshot(fetch=lambda url: {"items": []}, province_limit=1)
    tracks = snapshot["records"][0]["tracks"]
    assert tracks["woodworking"]["value"] is None
    assert tracks["metalworking"]["value"] is None
