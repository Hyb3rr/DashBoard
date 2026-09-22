from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_dashboard_uses_country_opportunity_read_model():
    template = (ROOT / "app" / "web" / "templates" / "dashboard.html").read_text(encoding="utf-8")
    javascript = (ROOT / "app" / "web" / "static" / "dashboard.js").read_text(encoding="utf-8")
    assert "Potential markets" in template
    assert "data-country-period=\"7d\"" in template
    assert "data-country-period=\"30d\"" in template
    assert "data-country-period=\"90d\"" in template
    assert "/api/country-opportunities" in javascript
    assert "period=${encodeURIComponent(countryDemandPeriod)}" in javascript
    assert "traffic_${countryDemandPeriod}" in javascript
    assert 'id="country-demand-scope"' in template
    assert "All countries" in javascript
    assert "loadCountryDemandCities" in javascript
    assert "/api/regions/${encodeURIComponent(code)}" in javascript
    assert "city_opportunities" in javascript
    assert "city_overall_opportunity" in javascript
    assert "province_profile?.provinces" in javascript
    assert "locality names are traffic context" in javascript
    assert "loadLegacyCountryDemandCities" not in javascript
    assert "traffic.get(String(row.city_id))" in javascript
    assert "normalizeCity" not in javascript
    assert "citySignalsFromProductMarkets" not in javascript
    assert "opportunity_score" in javascript
    assert "data-region-link" in javascript
    assert "window.location.assign(row.dataset.regionLink)" in javascript
    assert "/regions/${encodeURIComponent(code)}" in javascript
    assert "evidence_level" in javascript
    assert "traffic_${countryDemandPeriod}" in javascript
    assert "Market score" in javascript
    assert "country_demand_score" in javascript
    assert "not a probability of market success" not in javascript
    assert "This status describes data availability" not in javascript


def test_country_opportunity_details_use_responsive_side_sheet():
    javascript = (ROOT / "app" / "web" / "static" / "dashboard.js").read_text(encoding="utf-8")
    css = (ROOT / "app" / "web" / "static" / "dashboard.css").read_text(encoding="utf-8")
    assert "drawer.dataset.open='true'" in javascript
    assert "event.key==='Escape'" in javascript
    assert ".country-demand-drawer{position:fixed" in css
    assert "@media(max-width:700px)" in css


def test_classification_filter_scopes_dashboard_donut_counts():
    javascript = (ROOT / "app" / "web" / "static" / "dashboard.js").read_text(encoding="utf-8")
    assert "const allCounts=ipSummary?.classification" in javascript
    assert "Object.fromEntries(items.map(([key])=>[key,key===activeClassification" in javascript
    assert "const activeClassification=$(\'classification\')?.value||\'\';" in javascript


def test_clearing_classification_traffic_filter_resets_donut_selection():
    javascript = (ROOT / "app" / "web" / "static" / "dashboard.js").read_text(encoding="utf-8")
    assert "const wasClassification=trafficFilterType==='classification';" in javascript
    assert "$('classification').value='';" in javascript
    assert "renderClassificationAnalytics();" in javascript


def test_dashboard_uses_sse_events_and_fallback_polling_without_parallel_one_second_poll():
    javascript = (ROOT / "app" / "web" / "static" / "dashboard.js").read_text(encoding="utf-8")
    assert "function startDurableRealtimeSync" not in javascript
    assert "startRealtime();startDurableRealtimeSync()" not in javascript
    assert "function startFallbackPolling(){if(fallbackPollTimer)return;fallbackPollTimer=setInterval(()=>scheduleRealtimeFlush(),5000)}" in javascript
    assert "eventSource.addEventListener('ip_changes'" in javascript
    assert "const debounce=Math.max(750,Number(delay)||0)" in javascript
    assert "let trafficRequest=null" in javascript
    assert "if(trafficRequest)return trafficRequest" in javascript
