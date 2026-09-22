from pathlib import Path


def test_province_profile_ui_has_two_scopes_and_no_osm_product_ranking():
    template = Path("app/web/templates/region_detail.html").read_text()
    assert "Overall opportunity with source evidence" in template
    assert "Market opportunity" in template
    assert "Strong commercial context" in template
    assert "MutationObserver" not in template
    assert "decorateRegionDetail" in template
    assert "city_overall_opportunity" in template
    assert "Overall opportunity" in template
    assert "evidence_coverage" in template
    assert "Province / city profiles" in template
    assert 'data-scope="national">National context' in template
    assert "Observed enterprise base" in template
    assert 'value="overall"' in template
    assert "Search province" in template
    assert "Compare all" in template
    assert "HIGH OBSERVED BASE" in template
    assert "New foreign investment" in template
    assert "Cumulative foreign investment" in template
    assert "LIMITED OBSERVED BASE" in template
    assert "M</span>" in template
    assert "USDm" not in template
    assert "Not available" in template
    assert "Top local signals by product" not in template
    assert "Local Opportunities" not in template
    assert "No persisted area or city summary is available yet." not in template
    assert "lc3DemandGridRender" not in template


def test_region_source_links_have_scheme_guard():
    template = Path("app/web/templates/region_detail.html").read_text()
    security = Path("app/web/static/region-detail-security.js").read_text()
    assert "/static/region-detail-security.js" in template
    assert "a.source-link" in security
    assert "['http:', 'https:']" in security
    assert "event.preventDefault()" in security
