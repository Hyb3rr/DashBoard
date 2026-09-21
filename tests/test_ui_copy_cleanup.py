from pathlib import Path


ALERTS_HTML = Path("app/web/templates/alerts.html").read_text()
ALERTS_JS = Path("app/web/static/alerts.js").read_text()
DASHBOARD_CSS = Path("app/web/static/dashboard.css").read_text()
IP_DETAIL = Path("app/web/templates/ip_detail.html").read_text()
MAP_HTML = Path("app/web/templates/map.html").read_text()
DASHBOARD_JS = Path("app/web/static/dashboard.js").read_text()


def test_alerts_keep_titles_and_actions_without_redundant_description_copy():
    assert "Automatically explain Critical alerts" in ALERTS_HTML
    assert "Creates one asynchronous AI explanation" not in ALERTS_HTML
    assert "<h3 title=\"${esc(item.ip)}\">${esc(item.ip)}</h3>" in ALERTS_JS
    assert "<p>${esc(item.description)}</p>" not in ALERTS_JS
    assert 'data-status="acknowledged"' not in ALERTS_JS


def test_region_cards_hide_repeated_code_and_stale_metadata_under_title():
    assert ".grid .card-head > div > .eyebrow,.grid .signals > .meta{display:none}" in DASHBOARD_CSS


def test_ip_detail_removes_redundant_microcopy_but_keeps_primary_card_titles():
    assert "<h2>Assessment snapshot</h2><small>" not in IP_DETAIL
    assert "unique paths</span>" not in IP_DETAIL
    assert "first seen → last seen" not in IP_DETAIL
    assert "<h2>Network location</h2><small>" not in IP_DETAIL
    assert "<h2>Data freshness</h2><small>" not in IP_DETAIL
    assert "<h2>Assessment snapshot</h2>" in IP_DETAIL


def test_map_and_dashboard_remove_redundant_header_subtitles():
    assert "map-subtitle" not in MAP_HTML
    assert "subtitle:'Inspect network identities" not in DASHBOARD_JS
