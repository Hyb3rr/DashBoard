from pathlib import Path


ALERTS_JS = Path("app/web/static/alerts.js").read_text()


def test_alert_filters_start_a_fresh_generation_instead_of_appending_old_cards():
    assert "status.addEventListener('change', () => load(false));" in ALERTS_JS
    assert "const generation = ++loadGeneration;" in ALERTS_JS
    assert "if (generation !== loadGeneration) return;" in ALERTS_JS


def test_alert_load_more_remains_the_only_append_path():
    assert "const merged = loadMore ? renderedItems.concat" in ALERTS_JS
    assert "if (loadMore && busy) return;" in ALERTS_JS


def test_alerts_render_into_three_severity_columns_without_changing_pagination():
    html = Path("app/web/templates/alerts.html").read_text()
    css = Path("app/web/static/dashboard.css").read_text()
    assert 'class="alerts-board"' in html
    assert 'data-alert-column="low"' in html
    assert 'data-alert-column="medium"' in html
    assert 'data-alert-column="critical"' in html
    assert "const grouped = {low: [], medium: [], critical: []};" in ALERTS_JS
    assert "data-alert-items=\"${level}\"" in ALERTS_JS
    assert ".alerts-board{display:grid;grid-template-columns:repeat(3,minmax(0,1fr))" in css
    assert "@media(max-width:900px){.alerts-board{grid-template-columns:1fr}}" in css


def test_alerts_compact_controls_and_cards_avoid_redundant_content():
    html = Path("app/web/templates/alerts.html").read_text()
    css = Path("app/web/static/dashboard.css").read_text()
    assert 'class="alerts-intro"' not in html
    assert 'id="alert-severity"' not in html
    assert 'id="alert-status"' in html
    assert 'class="alerts-controls"' in html
    assert 'class="alerts-controls-right"' in html
    assert "const severity = document.getElementById('alert-severity')" not in ALERTS_JS
    assert "severity.addEventListener" not in ALERTS_JS
    assert 'data-ip="${esc(item.ip)}"' in ALERTS_JS
    assert 'Acknowledge' not in ALERTS_JS
    assert 'Resolve' not in ALERTS_JS
    assert '.alert-card,.alert-card *{min-width:0}' in css
    assert '.alert-card{overflow:hidden}' in css
    assert 'overflow-wrap:anywhere' in css
