from pathlib import Path


TEMPLATE = Path("app/web/templates/region_detail.html")


def test_vietnam_region_does_not_render_osm_product_ranking_panel():
    source = TEMPLATE.read_text(encoding="utf-8")
    assert "Top local signals by product" not in source
    assert "lc3DemandRender" not in source
    assert "lc3DemandGridRender" not in source
    assert "market-demand-grid" not in source
    assert "market-demand-card" not in source
    assert "installProvinceTabs" in source
    assert "Evidence profile" not in source
    assert "${marketStatus(r)}" in source
    assert "hero.querySelector('.market').innerHTML" not in source


def test_legacy_osm_product_evidence_is_not_rendered_by_region_template():
    source = TEMPLATE.read_text(encoding="utf-8")
    assert "observed local industry signals" not in source
    assert "OpenStreetMap · partial map coverage" not in source
