from app.services.country_demand import CountryDemandService
from app.core.country_demand import aggregate_session_observations


class FakeRepository:
    def __init__(self):
        self.calls = []

    def create_country_demand_snapshot(self, snapshot_id, period, threshold):
        self.calls.append(("create", snapshot_id, period, threshold))

    def write_country_demand_signals(self, snapshot_id, countries):
        self.calls.append(("write", snapshot_id, len(countries)))
        return len(countries)

    def publish_country_demand_snapshot(self, snapshot_id, count):
        self.calls.append(("publish", snapshot_id, count))
        return True


def row(code, session):
    return {"country_code": code, "session_id": session, "visitor_id": session, "engaged_session_depth": 2}


def test_session_aggregation_groups_declared_session_and_merges_evidence():
    result = aggregate_session_observations([
        {"session_id": "s1", "visitor_id": "v1", "country_code": "DE", "engaged": True, "engagement_seconds": 4, "pageviews": 1, "key_event_count": 0},
        {"session_id": "s1", "visitor_id": "v1", "country_code": "DE", "engaged": None, "engagement_seconds": 12, "pageviews": 3, "key_event_count": 1},
    ])
    assert len(result) == 1
    assert result[0]["identity_level"] == "session"
    assert result[0]["request_count"] == 2
    assert result[0]["engagement_seconds"] == 12
    assert result[0]["pageviews"] == 3
    assert result[0]["key_event_count"] == 1
    assert result[0].get("cf_js_detection_passed") is None


def test_session_aggregation_does_not_treat_missing_identity_as_one_session():
    result = aggregate_session_observations([{"country_code": "DE"}, {"country_code": "DE"}])
    assert len(result) == 2
    assert all(item["identity_level"] == "request_only" for item in result)
    assert all(item["session_id"] is None for item in result)


def test_session_aggregation_marks_country_conflict_without_traffic_scoring():
    result = aggregate_session_observations([
        {"session_id": "s1", "country_code": "DE", "geo_conflict": False},
        {"session_id": "s1", "country_code": "NL", "geo_conflict": False},
    ])
    assert result[0]["geo_conflict"] is True
    assert result[0]["geo_evidence"]["geo_conflict"] is True
    assert result[0]["traffic_status"] == "unknown"
    assert result[0]["geo_evidence"]["geo_conflict"] is True


def test_publish_writes_batch_before_publishing():
    repo = FakeRepository()
    service = CountryDemandService()
    result = service.publish_snapshot(repo, [row("TH", "s1")], [row("TH", "p1")], period="30d", snapshot_id="00000000-0000-0000-0000-000000000001")
    assert result["status"] == "published"
    assert [call[0] for call in repo.calls] == ["create", "write", "publish"]


def test_publish_rejects_unpublished_batch():
    repo = FakeRepository()
    repo.publish_country_demand_snapshot = lambda *_: False
    service = CountryDemandService()
    try:
        service.publish_snapshot(repo, [], [], snapshot_id="00000000-0000-0000-0000-000000000002")
    except RuntimeError as exc:
        assert "not published" in str(exc)
    else:
        raise AssertionError("expected publish failure")


def test_refresh_does_not_publish_when_clickhouse_has_no_current_events(monkeypatch):
    from app.services import country_demand

    monkeypatch.setattr(country_demand.clickhouse, "country_demand_events", lambda *_: [])
    repo = FakeRepository()
    result = CountryDemandService().refresh(repo)
    assert result["status"] == "no_data"
    assert repo.calls == []


def test_refresh_supports_all_published_periods(monkeypatch):
    from datetime import datetime, timezone
    from app.services import country_demand

    ranges = []
    monkeypatch.setattr(
        country_demand.clickhouse,
        "country_demand_events",
        lambda start, end, *_: ranges.append((start, end)) or [{"src_ip": "203.0.113.1", "cf_country": "TH"}],
    )
    monkeypatch.setattr(country_demand, "ProfileRepository", lambda: type("Profiles", (), {"country_demand_metadata": lambda self, ips: {}})())
    now = datetime(2026, 9, 10, tzinfo=timezone.utc)
    for period, days in (("7d", 7), ("30d", 30), ("90d", 90)):
        repo = FakeRepository()
        before = len(ranges)
        result = CountryDemandService().refresh(repo, now=now, period=period)
        assert result["status"] == "published"
        assert result["period"] == period
        assert (ranges[before][1] - ranges[before][0]).days == days
