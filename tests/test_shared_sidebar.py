from pathlib import Path


ROOT = Path(__file__).parents[1]
TEMPLATES = ROOT / "app/web/templates"


def test_all_pages_declare_shared_sidebar_mount():
    expected = {
        "dashboard.html": "dashboard",
        "alerts.html": "alerts",
        "map.html": "map",
        "raw_logs.html": "raw-logs",
        "regions.html": "regions",
        "ip_detail.html": "ip-detail",
    }
    for filename, page in expected.items():
        html = (TEMPLATES / filename).read_text()
        assert f'data-sidebar data-page="{page}"' in html
        assert "/static/sidebar.css" in html
        assert "/static/sidebar.js" in html

    detail = (TEMPLATES / "region_detail.html").read_text()
    assert "data-sidebar" not in detail
    assert "/static/sidebar.js" not in detail


def test_sidebar_script_owns_shared_navigation_and_preserves_collapse_state():
    script = (ROOT / "app/web/static/sidebar.js").read_text()
    assert "const items = [" in script
    assert "aside.innerHTML" in script
    assert "Global map" not in script
    assert "Region profiles" not in script
    assert "href: '/regions'" not in script
    assert "sentinel-sidebar-collapsed" in script
    assert "aria-current=\"page\"" in script
    assert "page === 'ip-detail' ? 'ip-intelligence'" in script


def test_sidebar_css_has_one_visual_contract():
    css = (ROOT / "app/web/static/sidebar.css").read_text()
    assert "grid-template-columns: 220px minmax(0, 1fr)" in css
    assert "padding: 18px 10px" in css
    assert "width: 30px" in css and "height: 30px" in css
    assert "text-transform: uppercase" in css
    assert "min-height: 38px" in css
    assert "var(--line" not in css
    assert "var(--raised" not in css
    assert "var(--secondary" not in css
    assert "var(--ink" not in css


def test_sidebar_behavior_script_does_not_inject_page_themed_css():
    script = (ROOT / "app/web/static/sidebar.js").read_text()
    assert "document.createElement('style')" not in script
    assert "class=\"nav nav-item" not in script
