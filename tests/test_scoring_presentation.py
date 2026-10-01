from pathlib import Path

from app.routers.ip_state import _dashboard_summary_fields


ROOT = Path(__file__).parents[1]


def test_scoring_ui_uses_distinct_risk_context_and_confidence_labels():
    ip_detail = (ROOT / "app/web/templates/ip_detail.html").read_text(encoding="utf-8")
    dashboard = (ROOT / "app/web/static/dashboard.js").read_text(encoding="utf-8")

    assert '<span class="label">Risk score</span>' in ip_detail
    assert 'id="hero-score-badge">Risk ${score}/100' in ip_detail
    assert "Assessment confidence (heuristic)" in ip_detail
    assert "<strong>Network context</strong>" in ip_detail
    assert "nonPublicAddress?'Not applicable'" in ip_detail
    assert "Tor/proxy/VPN/hosting context; not a verdict." in ip_detail
    assert "Risk score</span>" in dashboard
    assert "Assessment confidence (heuristic)" in dashboard
    assert "Network context</span>" in dashboard
    assert "'Not applicable'" in dashboard
    assert "not a verdict" in dashboard


def test_scoring_copy_preserves_existing_dashboard_api_projection_fields():
    result = _dashboard_summary_fields(
        observation={"requests": 12},
        classification={"score": 42, "label": "medium"},
        profile={"risk_score": 55},
    )

    assert result["profile_risk_score"] == 55
    assert result["effective_risk_score"] == 42
    assert result["effective_risk_level"] == "medium"
