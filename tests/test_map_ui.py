from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app


ROOT = Path(__file__).parents[1]


def test_map_page_and_assets_are_served():
    client = TestClient(app)
    page = client.get("/map")
    assert page.status_code == 200
    assert 'id="map-basemap"' in page.text
    assert 'data-mode="opportunity"' in page.text
    assert 'data-mode="combined"' not in page.text
    assert 'id="back-world"' not in page.text
    assert "/static/map.js" in page.text
    assert "maplibre-gl@4.7.1" in page.text
    assert client.get("/static/map.js").status_code == 200
    assert client.get("/static/map.css").status_code == 200


def test_dashboard_embeds_full_width_map_before_overview():
    client = TestClient(app)
    page = client.get("/")
    assert page.status_code == 200
    assert 'class="dashboard-map-card"' in page.text
    assert page.text.index('id="overview"') < page.text.index('class="dashboard-map-card"')
    assert page.text.index('class="dashboard-map-card"') < page.text.index('id="threats"')
    assert 'id="map-basemap"' in page.text
    assert '/static/map.js' in page.text
    assert 'id="dashboard-time-picker"' in page.text
    assert 'id="time-picker-trigger"' in page.text
    assert 'id="time-picker-popover"' in page.text
    assert 'id="calendar-days"' in page.text
    assert 'id="calendar-prev"' in page.text
    assert 'id="calendar-next"' in page.text
    assert 'placeholder="YYYY-MM-DD HH:mm"' in page.text
    assert 'type="datetime-local"' not in page.text
    assert 'data-range="30m"' in page.text
    assert 'data-range="30d"' in page.text
    assert 'id="traffic-start"' in page.text
    assert 'id="time-picker-apply"' in page.text
    assert 'Choose a start and end, then apply' in page.text
    assert 'id="traffic-end"' in page.text
    assert 'id="traffic-apply"' not in page.text
    assert 'id="traffic-clear"' not in page.text
    assert 'Choose a start and end, then apply' in page.text
    assert 'id="traffic-range"' not in page.text


def test_map_ui_keeps_threat_semantics_explicit():
    javascript = (ROOT / "app" / "web" / "static" / "map.js").read_text(encoding="utf-8")
    assert "/api/map/world?" in javascript
    assert "/api/map/world?" in javascript
    assert "flagged_ips" in javascript
    assert "threat_score" not in javascript
    assert "requests" in javascript
    assert "maplibregl.Map" in javascript
    assert "basemaps.cartocdn.com" in javascript
    assert "positron-gl-style" in javascript
    assert "applyMapTheme" in javascript
    assert "fitBounds" in javascript
    assert "zoom:1.25,minZoom:1.25" in javascript
    assert "countries.geojson" in javascript
    assert "countryAnchors" in javascript
    assert "mode==='opportunity'" in javascript
    assert "id:'intel-circles'" in javascript
    assert "id:'intel-hit-circles'" in javascript
    assert "function severityCounts" in javascript
    assert "function ensureSeverityRings" in javascript
    assert "intel-low-ring" in javascript
    assert "medium:['+'" in javascript
    assert "low:['+'" in javascript
    assert "['>', ['get','low'],0],'#55d6e8'" in javascript
    assert "critical:counts.critical" in javascript
    assert "medium:counts.medium" in javascript
    assert "low:counts.low" in javascript
    assert "toFixed(1)" in javascript
    assert "map-tooltip').hidden=true" in javascript
    assert "mode==='combined'" not in javascript
    assert 'html[data-theme="light"] .map-stage .map-tooltip' in (ROOT / "app" / "web" / "static" / "map.css").read_text(encoding="utf-8")
    dashboard_javascript = (ROOT / "app" / "web" / "static" / "dashboard.js").read_text(encoding="utf-8")
    assert "window.getDashboardTimeWindow" in dashboard_javascript
    assert "window.setDashboardMapRange" in dashboard_javascript
    assert "window.reloadDashboardMap" in dashboard_javascript
    assert "dashboard-time-window-change" in dashboard_javascript
    assert "time-picker-apply" in javascript
    assert "applyButton?.click()" in javascript
    assert "event.stopPropagation();const [year,month,day]" in javascript
    assert "if(startInput.value&&endInput.value)window.applyDashboardTimeWindow?.()" not in javascript
    assert "mapTimeParams" in javascript
    assert "mapRequestSequence" in javascript
    assert "start" in javascript
    assert "end" in javascript
    assert "maplibre-gl" in (ROOT / "app" / "web" / "templates" / "map.html").read_text(encoding="utf-8")
    assert 'class="legend-dot low"' in (ROOT / "app" / "web" / "templates" / "map.html").read_text(encoding="utf-8")


def test_map_ui_uses_maplibre_geojson_layers_instead_of_custom_webgl_renderer():
    javascript = (ROOT / "app" / "web" / "static" / "map.js").read_text(encoding="utf-8")
    assert "addSource('intel-points'" in javascript
    assert "setData({type:'FeatureCollection',features})" in javascript
    assert "id:'intel-cluster-circles'" in javascript
    assert "id:'intel-cluster-labels'" in javascript
    assert "mapAnchor" in javascript
    assert "item?.marker_scope!=='country_aggregate'" in javascript
    assert "mapState.countryAnchors[wanted]" in javascript
    assert "map$('map-empty').hidden=!zoomVisible||features.length>0" in javascript
    assert "function bindIntelClick" not in javascript
    assert "iso_3166_1" in javascript
    assert "fitBounds" in javascript
    assert "createBuffer" not in javascript
    assert "WORLD_BASEMAP" not in javascript
    assert "threat_score" not in javascript


def test_map_ui_decision_lens_keeps_dimensions_separate():
    javascript = (ROOT / "app" / "web" / "static" / "map.js").read_text(encoding="utf-8")
    template = (ROOT / "app" / "web" / "templates" / "map.html").read_text(encoding="utf-8")
    assert "renderDecisionLens" in javascript
    assert "decision-opportunity" in template
    assert "decision-security" in template
    assert "decision-cell" in template
    assert "no combined score is calculated" in template
    assert "threat_score" not in javascript


def test_map_ui_surfaces_freshness_and_geo_coverage():
    javascript = (ROOT / "app" / "web" / "static" / "map.js").read_text(encoding="utf-8")
    template = (ROOT / "app" / "web" / "templates" / "map.html").read_text(encoding="utf-8")
    assert "function freshness" in javascript
    assert "selected-opportunity-age" in template
    assert "selected-threat-age" in template
    assert "selected-geo-coverage" in template
    assert "city_coverage" in javascript
    assert "Age is measured against the current read-model snapshot." in template


def test_map_ui_has_cartographic_context_and_focus_states():
    template = (ROOT / "app" / "web" / "templates" / "map.html").read_text(encoding="utf-8")
    css = (ROOT / "app" / "web" / "static" / "map.css").read_text(encoding="utf-8")
    assert "RESOLVED GEO · READ ONLY" in template
    assert "Click a marker to inspect" in template
    assert ".map-context" in css
    assert ":focus-visible" in css
    assert "prefers-reduced-motion" not in css or "transition" in css
