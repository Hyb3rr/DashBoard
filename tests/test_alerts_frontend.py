from pathlib import Path


ALERTS_JS = Path("app/web/static/alerts.js").read_text()


def test_alert_filters_start_a_fresh_generation_instead_of_appending_old_cards():
    assert "status.addEventListener('change', () => load(false));" in ALERTS_JS
    assert "const generation = ++loadGeneration;" in ALERTS_JS
    assert "if (generation !== loadGeneration) return;" in ALERTS_JS


def test_alert_load_more_remains_the_only_append_path():
    assert "const merged = loadMore ? renderedItems.concat" in ALERTS_JS
    assert "if (loadMore && busy) return;" in ALERTS_JS


def test_alert_board_shows_only_the_highest_current_severity_per_ip():
    assert "function selectCurrentCaseAlerts(items)" in ALERTS_JS
    assert "const severityRank = {low: 1, medium: 2, critical: 3};" in ALERTS_JS
    assert "const currentCases = selectCurrentCaseAlerts(visibleItems)" in ALERTS_JS
    assert ".filter(item => !status.value || item.status === status.value)" in ALERTS_JS
    assert "query.set('status', status.value)" not in ALERTS_JS
    assert "alert event" in ALERTS_JS


def test_alert_reason_uses_human_readable_behavior_from_evidence():
    assert "function alertBehavior(item)" in ALERTS_JS
    assert "return 'Sensitive path probing'" in ALERTS_JS
    assert "return 'Brute-force login attempts'" in ALERTS_JS
    assert "return 'Rare path activity'" in ALERTS_JS
    assert "return 'Path enumeration'" in ALERTS_JS
    assert "return 'Request burst'" in ALERTS_JS
    assert "networkSignals.push('Proxy')" in ALERTS_JS
    assert "networkSignals.push('VPN')" in ALERTS_JS
    assert "networkSignals.push('Tor exit')" in ALERTS_JS
    assert "networkSignals.push('Hosting/datacenter')" in ALERTS_JS
    assert "return 'Security risk signals'" in ALERTS_JS
    assert '<span>Detected behavior</span>' in ALERTS_JS
    assert 'title="${esc(item.reason_type)}"' not in ALERTS_JS


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
