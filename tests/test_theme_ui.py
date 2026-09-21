from fastapi.testclient import TestClient

from app.main import app


def test_product_pages_expose_shared_light_dark_theme_contract():
    client = TestClient(app)
    pages = ["/", "/alerts", "/map", "/regions", "/ip/8.8.8.8"]
    for path in pages:
        response = client.get(path)
        assert response.status_code == 200, path
    assert 'html[data-theme="light"]' in client.get("/static/dashboard.css").text
    assert 'html[data-theme="light"]' in client.get("/static/map.css").text


def test_shared_theme_scripts_toggle_and_persist_theme():
    client = TestClient(app)
    dashboard = client.get("/static/dashboard.js").text
    alerts = client.get("/static/alerts.js").text
    assert "localStorage.setItem('sentinel-theme',theme)" in dashboard
    assert "document.documentElement.dataset.theme=theme" in dashboard
    assert "localStorage.setItem('sentinel-theme', theme)" in alerts
    assert "document.documentElement.dataset.theme = theme" in alerts


def test_dashboard_and_map_have_one_global_theme_owner():
    dashboard = TestClient(app).get("/static/dashboard.js").text
    map_script = TestClient(app).get("/static/map.js").text
    assert "sentinel-theme-change" in dashboard
    assert "themeToggle.addEventListener('click'" not in map_script
    assert "sentinel-theme-change" in map_script


def test_map_rehydrates_custom_layers_after_theme_style_reload():
    map_script = TestClient(app).get("/static/map.js").text
    assert "discoverCountryLabelLayers();ensureIntelLayers();ensureSeverityRings();" in map_script
    assert "mapState.map.once('idle'" in map_script
    assert "mapState.map.triggerRepaint()" in map_script
