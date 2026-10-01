from pathlib import Path


IP_DETAIL = Path("app/web/templates/ip_detail.html").read_text(encoding="utf-8")


def test_ip_detail_history_renders_transitions_evidence_and_legacy_gaps():
    assert "function classificationHistoryMarkup(items,currentLabel)" in IP_DETAIL
    assert "item.previous_classification" in IP_DETAIL
    assert "item.current_classification" in IP_DETAIL
    assert "after.evidence" in IP_DETAIL
    assert "item.source==='change_log'" in IP_DETAIL
    assert "Highest recorded:" in IP_DETAIL
    assert "Show ${older.length} older state change" in IP_DETAIL


def test_ip_detail_history_refreshes_with_realtime_profile_state():
    assert "if(history)history.innerHTML=classificationHistoryMarkup(d.classification_history,c.label)" in IP_DETAIL
    assert "Current state is recalculated from recent behavior and network signals." in IP_DETAIL
