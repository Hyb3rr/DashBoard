from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_vietnam_city_table_uses_country_demand_cohort_and_selected_period():
    javascript = (ROOT / "app" / "web" / "static" / "dashboard.js").read_text(encoding="utf-8")

    assert "isVietnam?fetch(apiUrl(`/api/country-opportunities?period=${encodeURIComponent(countryDemandPeriod)}`)" in javascript
    assert "provinceRequests=new Map((cityTraffic.provinces||[])" in javascript
    assert "cityTraffic.conservation!==true" in javascript
    assert "Unmapped / unknown city" in javascript
    assert "Qualified requests · ${countryDemandPeriod}" in javascript
    assert "<th>Observed users</th>" in javascript
    assert "t.observed_ips==null?'0':num(t.observed_ips)" in javascript
    assert "score.evidence_coverage==null?null:Number(score.evidence_coverage)/100" in javascript
    assert "api/map/country/${encodeURIComponent(code)}?range=30d" in javascript


def test_country_market_traffic_never_falls_back_to_group_count_as_http_requests():
    javascript = (ROOT / "app" / "web" / "static" / "dashboard.js").read_text(encoding="utf-8")

    assert "row[`qualified_http_requests_${countryDemandPeriod}`]" in javascript
    assert "requestCount==null?'—':num(requestCount)" in javascript
    assert "row[`traffic_${countryDemandPeriod}`]" not in javascript


def test_period_change_preserves_the_selected_country_demand_view():
    javascript = (ROOT / "app" / "web" / "static" / "dashboard.js").read_text(encoding="utf-8")

    assert "function reloadCountryDemandView()" in javascript
    assert "if(scope==='all')return loadCountryDemandSignals();" in javascript
    assert "return loadCountryDemandCities(scope)" in javascript
    assert "item.classList.toggle('active',item===button));reloadCountryDemandView()" in javascript
