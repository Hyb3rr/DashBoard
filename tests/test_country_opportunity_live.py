from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_dashboard_renders_confidence_aware_opportunity_fields():
    javascript = (ROOT / "app" / "web" / "static" / "dashboard.js").read_text(encoding="utf-8")
    assert "opportunity_status||c.opportunity_state" in javascript
    assert "adjusted_demand_score" in javascript
    assert "weighted_qualified_sessions" in javascript
    assert "demand_confidence" in javascript
    assert "Adjusted demand" in javascript


def test_country_opportunity_table_hides_confidence_column():
    javascript = Path("app/web/static/dashboard.js").read_text()
    assert "<th>Confidence</th>" not in javascript
    assert "c.demand_confidence" in javascript
