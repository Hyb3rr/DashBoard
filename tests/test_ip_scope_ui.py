from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]


def test_compact_ip_rows_expose_address_scope_without_changing_classification():
    from app.routers.ip_state import _pg_compact_item

    item = _pg_compact_item({
        "ip": "169.254.130.1",
        "label": "low",
        "classification_score": 15,
        "classification_confidence": 75,
        "provider_status": {},
        "observation_payload": {"requests": 2509},
    })

    assert item["address_scope"] == "link_local"
    assert item["is_non_public"] is True
    assert item["threat_signal_label"] == "low"
    assert item["threat_signal_score"] == 15
    assert item["requests"] == 2509


def test_dashboard_explains_scope_tags_and_keeps_abuse_signals_compact():
    template = (ROOT / "app/web/templates/dashboard.html").read_text(encoding="utf-8")
    script = (ROOT / "app/web/static/dashboard.js").read_text(encoding="utf-8")
    css = (ROOT / "app/web/static/dashboard.css").read_text(encoding="utf-8")

    assert "Scope tags describe the address range only" in template
    assert "does not affect risk score or traffic totals" in script
    assert "Shared CGNAT" in script
    assert "link_local:'Local'" in script
    assert "scope-tag-local" in script
    assert "tag==='intel:abuse_historical'||tag==='intel:abuse_persistent'" in script
    assert "compact-abuse" in script
    assert ".flag.compact-abuse" in css
    assert "font-size:9px" in css
    assert "white-space:nowrap" in css
    assert ".scope-tag-local" in css
    assert 'html[data-theme="light"] .scope-tag-local' in css


def test_signal_column_keeps_fixed_layout_when_filters_replace_rows():
    css = (ROOT / "app/web/static/dashboard.css").read_text(encoding="utf-8")
    script = (ROOT / "app/web/static/dashboard.js").read_text(encoding="utf-8")

    assert "#network-identities .table-wrap table{width:100%;min-width:1170px;table-layout:fixed}" in css
    assert "#network-identities .table-wrap th:nth-child(7),#network-identities .table-wrap td:nth-child(7){width:11.97%}" in css
    assert "$('rows').innerHTML=filtered.length?filtered.map(x=>{" in script
    assert "#network-identities .table-wrap tbody#rows td:nth-child(7) .flag.compact-abuse" in css


@pytest.mark.parametrize(
    "refresh_marker",
    [
        "['privacy','disposition'].forEach",
        "$('classification').addEventListener('input'",
        "$('search').addEventListener('input'",
        "document.querySelectorAll('th.sortable').forEach(th=>th.addEventListener('click'",
        "$('ip-prev').addEventListener('click'",
        "$('ip-next').addEventListener('click'",
    ],
)
def test_ip_table_filter_and_navigation_refreshes_use_same_render_path(refresh_marker):
    script = (ROOT / "app/web/static/dashboard.js").read_text(encoding="utf-8")
    start = script.index(refresh_marker)
    handler_line = script[start : script.find("\n", start)]

    assert "loadIpSnapshot(true)" in handler_line
