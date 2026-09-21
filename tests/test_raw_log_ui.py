from pathlib import Path


def test_raw_log_tail_page_is_raw_first_and_bounded():
    html = Path("app/web/templates/raw_logs.html").read_text(encoding="utf-8")
    javascript = Path("app/web/static/raw-logs.js").read_text(encoding="utf-8")
    assert "Raw Log Tail" in html
    assert "id=\"raw-log-pause\"" in html
    assert "id=\"raw-log-clear\"" in html
    assert "max 100 events" in html
    assert "e.raw_line" in javascript
    assert "raw-log-table" in javascript
    assert "<thead>" in javascript
    assert "status>=500?'error'" in javascript
    assert "raw-log-status-code" in javascript
    assert 'href="/ip/${encodeURIComponent(e.ip)}"' in javascript
    assert "slice(-100)" in javascript
    assert "/api/raw-logs/tail" in javascript
    assert "sentinel-theme" in javascript
    assert "themeToggle.addEventListener" in javascript
