import asyncio
from pathlib import Path

from app.routers import ip_detail
from app.routers import ip_state


def test_ip_detail_returns_snapshot_and_schedules_missing_enrichment(monkeypatch):
    scheduled = []
    snapshot = {"ip": "8.8.8.8", "enrichment_status": "partial", "network_location": {}}
    class EmptyAi:
        def scores(self, _ips):
            return []

    monkeypatch.setattr(ip_detail.StateRepository, "get", lambda _self, _ip: snapshot)
    monkeypatch.setattr(ip_detail, "AiRepository", EmptyAi)
    monkeypatch.setattr(ip_detail.collector, "schedule_enrichment", lambda ip: scheduled.append(ip))
    monkeypatch.setattr(ip_detail, "_pg_item", lambda row: row)

    result = asyncio.run(ip_detail.ip_details("8.8.8.8"))

    assert result is snapshot
    assert scheduled == ["8.8.8.8"]


def test_non_public_ip_is_terminal_and_never_schedules_enrichment(monkeypatch):
    scheduled = []
    class EmptyAi:
        def scores(self, _ips):
            return []

    monkeypatch.setattr(ip_detail.StateRepository, "get", lambda _self, ip: {"ip": ip, "enrichment_status": "complete", "network_location": {}})
    monkeypatch.setattr(ip_detail, "AiRepository", EmptyAi)
    monkeypatch.setattr(ip_detail.collector, "schedule_enrichment", lambda ip: scheduled.append(ip))
    monkeypatch.setattr(ip_detail, "_pg_item", lambda row: row)

    for ip in ("169.254.129.1", "10.0.0.1", "127.0.0.1"):
        asyncio.run(ip_detail.ip_details(ip))

    assert scheduled == []


def test_non_public_enrichment_exposes_address_scope():
    from app.core.enrichment import lookup

    for ip, expected in (("10.0.0.1", "private"), ("127.0.0.1", "loopback"), ("169.254.1.1", "link_local"), ("100.64.0.1", "shared_cgnat"), ("192.0.2.1", "documentation"), ("2001:db8::1", "documentation")):
        result = asyncio.run(lookup(ip))
        assert result["address_scope"] == expected
        assert result["is_private"] is True


def test_ip_detail_refresh_never_runs_enrichment_inline(monkeypatch):
    scheduled = []
    snapshot = {"ip": "8.8.8.8", "enrichment_status": "complete", "network_location": {"ip2region": "known"}}
    class EmptyAi:
        def scores(self, _ips):
            return []

    monkeypatch.setattr(ip_detail.StateRepository, "get", lambda _self, _ip: snapshot)
    monkeypatch.setattr(ip_detail, "AiRepository", EmptyAi)
    monkeypatch.setattr(ip_detail.collector, "schedule_enrichment", lambda ip: scheduled.append(ip))
    monkeypatch.setattr(ip_detail, "_pg_item", lambda row: row)

    result = asyncio.run(ip_detail.ip_details("8.8.8.8", refresh=True))

    assert result is snapshot
    assert scheduled == ["8.8.8.8"]


def test_complete_enrichment_without_ip2region_does_not_reschedule(monkeypatch):
    scheduled = []
    snapshot = {"ip": "8.8.8.8", "enrichment_status": "complete", "network_location": {}}

    class EmptyAi:
        def scores(self, _ips):
            return []

    monkeypatch.setattr(ip_detail.StateRepository, "get", lambda _self, _ip: snapshot)
    monkeypatch.setattr(ip_detail, "AiRepository", EmptyAi)
    monkeypatch.setattr(ip_detail.collector, "schedule_enrichment", lambda ip: scheduled.append(ip))
    monkeypatch.setattr(ip_detail, "_pg_item", lambda row: row)

    asyncio.run(ip_detail.ip_details("8.8.8.8"))

    assert scheduled == []


def test_ip_detail_realtime_contract_filters_by_ip_and_debounces():
    html = (Path(__file__).parents[1] / "app" / "web" / "templates" / "ip_detail.html").read_text(encoding="utf-8")
    assert "new EventSource('/api/stream')" in html
    assert "payload.ips" in html
    assert "},350);" in html
    assert "refreshDetailLive()" in html
    assert "loadIpTraffic(false)" in html
    assert "try{await load()}finally" not in html
    assert "location.reload" not in html
    assert "trafficRequestSequence" in html
    assert "trafficRenderKey" in html
    assert "chart.replaceChildren(...nextChart.childNodes)" in html
    assert "data-case-start=\"${esc(d.first_seen||o.first_seen||'')}\"" in html
    assert "data-case-end=\"${esc(d.last_seen||o.last_seen||'')}\"" in html
    assert "d.first_seen||o.first_seen" in html
    assert "d.last_seen||o.last_seen" in html
    assert "endDate>=startDate" in html
    assert "endDate.getTime()===startDate.getTime()" in html
    assert "const padding=30*60*1000" in html
    assert "selectCaseTrafficWindow" in html
    assert "trafficRange='case'" in html


def test_ip_detail_prioritizes_traffic_and_compacts_score_explanation():
    html = (Path(__file__).parents[1] / "app" / "web" / "templates" / "ip_detail.html").read_text(encoding="utf-8")
    assert html.index('<section class="card ip-traffic"') < html.index('${scoreExplainer(b,c)}')
    assert '<section class="card score-explainer" data-investigation-section="detections">' in html
    assert '<h2>Detection breakdown</h2>' in html
    assert 'Why this verdict?' not in html
    assert 'How this score is calculated' not in html
    assert "if(requestSequence!==trafficRequestSequence)return" in html
    assert 'data-ip-range="case">Case span' in html
    assert "data.range==='case'?'case span'" in html
    assert 'data-investigation-tab="overview"' in html
    assert 'data-investigation-tab="activity"' in html
    assert 'data-investigation-tab="detections"' in html
    assert 'data-investigation-tab="evidence"' in html
    assert 'data-investigation-tab="intel"' in html
    assert "setInvestigationTab('overview')" in html
    assert 'Assessment snapshot' in html
    assert 'Detection highlights' in html
    assert 'class="investigation-evidence-grid" data-investigation-section="evidence"' in html
    assert 'investigationLayout.dataset.activeTab=tab' in html
    assert 'class="classification-value ${(label||\'unknown\').toLowerCase()}"' in html
    assert '.overview-snapshot .classification-value.critical{color:var(--red)}' in html
    assert '.overview-snapshot .classification-value.medium{color:var(--yellow)}' in html
    assert '.overview-snapshot .classification-value.low{color:var(--low)}' in html


def test_ip_state_preserves_zero_persisted_score_for_unknown_label(monkeypatch):
    monkeypatch.setattr(ip_state, "classify_ip", lambda *args: {
        "label": "good", "score": 5, "confidence": 70, "summary": "computed"
    })
    result = ip_state._pg_item({
        "ip": "51.68.107.149",
        "label": "unknown",
        "classification_score": 0,
        "classification_confidence": 0,
        "observation_payload": {},
    })
    assert result["classification"]["label"] == "unknown"
    assert result["classification"]["score"] == 0
    assert result["classification"]["confidence"] == 0
    assert result["threat_signal_score"] == 0


def test_ip_state_uses_geo_resolution_when_profile_location_is_empty(monkeypatch):
    monkeypatch.setattr(ip_state, "classify_ip", lambda *args: {"label": "good", "score": 5, "confidence": 70})
    result = ip_state._pg_item({
        "ip": "47.82.55.98", "network_location": {}, "country": None, "country_code": None,
        "observation_payload": {}, "geo_country": "Singapore", "geo_country_code": "SG",
        "geo_city": "Singapore", "geo_asn": "45102", "geo_organization": "Alibaba Cloud LLC",
        "geo_network_type": "hosting", "geo_confidence": 85, "geo_disputed": False,
        "geo_location_scope": "network", "classification_score": 5, "classification_confidence": 70,
    })
    assert result["country"] == "Singapore"
    assert result["country_code"] == "SG"
    assert result["network_location"]["country"] == "Singapore"


def test_ip_state_prefers_non_empty_profile_location_over_geo_cache(monkeypatch):
    monkeypatch.setattr(ip_state, "classify_ip", lambda *args: {"label": "good", "score": 5, "confidence": 70})
    result = ip_state._pg_item({
        "ip": "47.82.55.98", "network_location": {"country": "Singapore", "country_code": "SG", "sources": ["profile"]},
        "country": "Singapore", "country_code": "SG", "observation_payload": {},
        "geo_country": "Malaysia", "geo_country_code": "MY", "classification_score": 5,
        "classification_confidence": 70,
    })
    assert result["network_location"]["sources"] == ["profile"]
    assert result["country_code"] == "SG"


def test_ip_detail_ai_explain_is_manual_and_polls_validated_result():
    html = (Path(__file__).parents[1] / "app" / "web" / "templates" / "ip_detail.html").read_text(encoding="utf-8")
    assert "Explain with AI" in html
    assert "/api/ai/cases/${encodeURIComponent(ip)}/explain" in html
    assert "/api/ai/jobs/${encodeURIComponent(aiJobId)}" in html
    assert "setTimeout(()=>{aiPollTimer=null;pollAiJob()},3000)" in html
    assert "grounding validated" in html
    assert "automatic retry" in html
    assert "classification or risk" in html
    assert "renderAiExplainInPlace()" in html
    assert "next.hidden=current.hidden" in html
    assert "aiJobState=await res.json();" in html
    assert "scheduleAiPoll();" in html
    assert "renderAiExplainInPlace();" in html
    assert "status_unavailable: ${error.message}`};renderAiExplainInPlace()" in html
    assert "Rare path · ${item.path}" in html
    assert "Evidence ID · ${esc(id||'unknown')}" not in html


def test_classification_labels_are_not_presented_as_severity_levels():
    detail_html = (Path(__file__).parents[1] / "app" / "web" / "templates" / "ip_detail.html").read_text(encoding="utf-8")
    dashboard_html = (Path(__file__).parents[1] / "app" / "web" / "static" / "dashboard.js").read_text(encoding="utf-8")
    assert "critical:'Critical'" in detail_html
    assert "medium:'Medium'" in detail_html
    assert "low:'Low'" in detail_html
    assert "{good:'Low',watch:'Medium',bad:'Critical'" not in detail_html
    assert "critical:'Critical',medium:'Medium',low:'Low',good:'Good'" in dashboard_html
    assert "['low','Low','var(--low)']" in dashboard_html
    assert "['good','Good','var(--stable)']" in dashboard_html


def test_ip_intelligence_compact_location_preserves_country_candidates():
    router_source = (Path(__file__).parents[1] / "app" / "routers" / "ip_state.py").read_text(encoding="utf-8")
    assert 'for key in ("status", "resolved", "candidates")' in router_source


def test_enrichment_change_log_is_written_on_same_transaction(monkeypatch):
    from app.services import profiles

    class Connection:
        def __init__(self):
            self.executed = []

        def execute(self, sql, params=()):
            self.executed.append((sql, params))

    class Scope:
        def __init__(self, connection):
            self.connection = connection

        def __enter__(self):
            return self.connection

        def __exit__(self, *exc):
            return False

    connection = Connection()
    written = []
    monkeypatch.setattr(profiles, "transaction", lambda: Scope(connection))
    monkeypatch.setattr(profiles.ProfileRepository, "get", lambda _self, _ip: None)
    monkeypatch.setattr(profiles.ProfileRepository, "upsert", lambda _self, data, conn=None: written.append(conn))
    monkeypatch.setattr(profiles.GeoRepository, "persist_resolution", lambda *args, **kwargs: None)
    async def lookup(_ip, attempt, refresh):
        return {"ip": _ip, "enrichment_status": "complete"}
    monkeypatch.setattr(profiles, "lookup", lookup)

    result, error = __import__("asyncio").run(
        profiles.ensure_profile_postgres("192.0.2.30", change_reason="enrichment")
    )

    assert error is None
    assert result["ip"] == "192.0.2.30"
    assert written == [connection]
    assert any("ip_change_log" in sql for sql, _ in connection.executed)


def test_enrichment_reclassifies_existing_observation_when_identity_changes(monkeypatch):
    from app.services import profiles

    class Result:
        def __init__(self, row):
            self.row = row

        def fetchone(self):
            return self.row

    class Connection:
        def __init__(self):
            self.executed = []

        def execute(self, sql, params=()):
            self.executed.append((sql, params))
            if "SELECT payload FROM ip_observations_state" in sql:
                return Result({"payload": {"recent_behavior_score": 0, "recent_behavior_evidence": []}})
            if "SELECT label,score FROM ip_classification_state" in sql:
                return Result({"label": "good", "score": 0})
            return Result(None)

    class Scope:
        def __init__(self, connection):
            self.connection = connection

        def __enter__(self):
            return self.connection

        def __exit__(self, *exc):
            return False

    connection = Connection()
    monkeypatch.setattr(profiles, "transaction", lambda: Scope(connection))
    monkeypatch.setattr(profiles.ProfileRepository, "get", lambda _self, _ip: None)
    monkeypatch.setattr(profiles.ProfileRepository, "upsert", lambda *args, **kwargs: None)
    monkeypatch.setattr(profiles.GeoRepository, "persist_resolution", lambda *args, **kwargs: None)
    monkeypatch.setattr(profiles, "classify_ip", lambda *args: {
        "label": "critical", "score": 90, "confidence": 80, "evidence": ["Tor exit signal"],
    })

    async def lookup(_ip, attempt, refresh):
        return {"ip": _ip, "is_tor": True, "enrichment_status": "complete"}

    monkeypatch.setattr(profiles, "lookup", lookup)
    result, error = asyncio.run(profiles.ensure_profile_postgres("192.0.2.31", refresh=True))

    assert error is None
    assert result["enrichment_status"] == "complete"
    assert any("INSERT INTO ip_classification_state" in sql for sql, _ in connection.executed)
    assert any("enrichment_classification" in sql for sql, _ in connection.executed)
    assert any("INSERT INTO alert_outbox" in sql for sql, _ in connection.executed)


def test_same_profile_refresh_does_not_write_change_log(monkeypatch):
    from app.services import profiles

    class Connection:
        def __init__(self):
            self.executed = []

        def execute(self, sql, params=()):
            self.executed.append((sql, params))

    class Scope:
        def __init__(self, connection):
            self.connection = connection

        def __enter__(self):
            return self.connection

        def __exit__(self, *exc):
            return False

    connection = Connection()
    previous = {"ip": "8.8.8.8", "country": "US", "provider_status": {"feed": {"status": "active", "checked_at": "old"}}, "enrichment_status": "complete"}
    current = {**previous, "provider_status": {"feed": {"status": "active", "checked_at": "new"}}, "fetched_at": "new", "enrichment_attempts": 2}
    monkeypatch.setattr(profiles, "transaction", lambda: Scope(connection))
    monkeypatch.setattr(profiles.ProfileRepository, "get", lambda _self, _ip: previous)
    monkeypatch.setattr(profiles.ProfileRepository, "upsert", lambda _self, data, conn=None: None)
    monkeypatch.setattr(profiles.GeoRepository, "persist_resolution", lambda *args, **kwargs: None)
    async def lookup(_ip, attempt, refresh):
        return current
    monkeypatch.setattr(profiles, "lookup", lookup)

    _, error = asyncio.run(profiles.ensure_profile_postgres("8.8.8.8", refresh=True, change_reason="enrichment"))

    assert error is None
    assert not any("ip_change_log" in sql for sql, _ in connection.executed)
