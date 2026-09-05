from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_dashboard_keeps_realtime_stream_without_preliminary_alert_panel():
    html = (ROOT / "app" / "web" / "templates" / "dashboard.html").read_text(encoding="utf-8")
    javascript = (ROOT / "app" / "web" / "static" / "dashboard.js").read_text(encoding="utf-8")

    assert 'id="early-alert-list"' not in html
    assert "addEventListener('early_alert',handleEarlyAlert)" not in javascript


def test_dashboard_keeps_ip_realtime_updates():
    javascript = (ROOT / "app" / "web" / "static" / "dashboard.js").read_text(encoding="utf-8")

    assert "addEventListener('ip_changes'" in javascript
