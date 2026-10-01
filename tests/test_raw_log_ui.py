from pathlib import Path


def test_raw_log_tail_page_is_raw_first_and_bounded():
    html = Path("app/web/templates/raw_logs.html").read_text(encoding="utf-8")
    javascript = Path("app/web/static/raw-logs.js").read_text(encoding="utf-8")
    assert "Raw Log Tail" in html
    assert "id=\"raw-log-pause\"" in html
    assert "id=\"raw-log-clear\"" in html
    assert ">Clear filters</button>" in html
    assert 'id="raw-log-window"' in html
    assert 'role="combobox"' in html and 'id="raw-log-ip-suggestions"' in html
    assert "raw-logs.js?v=20260928-raw-clear-filters" in html
    assert 'value="3600"' in html and 'value="21600"' in html
    assert 'value="43200"' in html and 'value="86400"' in html
    assert 'id="raw-log-older"' not in html
    assert 'role="log"' in html
    assert "height:min(62vh,720px);overflow:auto" in html
    assert "white-space:pre-wrap;overflow-wrap:anywhere" in html
    assert "raw-log-method.get" in html and "raw-log-method.post" in html
    assert "event.raw_line" in javascript
    assert "raw-log-line" in javascript
    assert "lineMarkup(event)" in javascript
    assert "raw-log-method ${method}" in javascript
    assert "raw-log-ip-token" in javascript and "raw-log-ip-token" in html
    assert "<strong class=\"raw-log-ip-token\">" in javascript
    assert "raw-log-status-code ${statusTone}" in javascript
    assert "status>=500?'error':status>=400?'warn':status>=300?'redirect':status>=200?'ok'" in javascript
    assert "list.scrollTop=list.scrollHeight" in javascript
    assert "list.addEventListener('scroll'" in javascript
    assert "list.scrollTop<=32" in javascript
    assert "loadOlderPage()" in javascript
    assert "function loadOlderPage()" in javascript
    assert "api/raw-logs/ip-suggestions" in javascript
    assert "setTimeout(loadIpSuggestions,300)" in javascript
    assert "ipFilter.value.trim().length<2" in javascript
    assert "event.key==='ArrowDown'||event.key==='ArrowUp'" in javascript
    assert "selectIpSuggestion(suggestionItems[suggestionIndex])" in javascript
    assert "else commitIpFilter();return" in javascript
    assert "ip=appliedIp" in javascript
    assert "before_event_id" in javascript
    assert "ipFilter.value='';appliedIp='';$('raw-log-status').value=''" in javascript
    assert "closeIpSuggestions();loadHistory()" in javascript
    assert "list.scrollTop=previousTop+(list.scrollHeight-previousHeight)" in javascript
    assert "request(query(300))" in javascript
    assert "/api/raw-logs/tail" in javascript
    assert "sentinel-theme" in javascript
    assert "themeToggle.addEventListener" in javascript
