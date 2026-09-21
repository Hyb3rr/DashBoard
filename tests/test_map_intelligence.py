from datetime import datetime, timezone
from pathlib import Path

from app.services.map_intelligence import MapIntelligenceService, _canonical_vn_traffic, _utc_iso


def test_vietnam_traffic_attaches_to_canonical_province_and_preserves_unmapped():
    rows, unmapped = _canonical_vn_traffic({"cities": [
        {"city_key": "hanoi", "city_name": "Hà Nội", "observed_ips": 2, "requests": 188,
         "latitude": 21.0, "longitude": 105.8},
        {"city_key": "vinhomes times city", "city_name": "Vinhomes Times City", "observed_ips": 1, "requests": 2},
    ]})
    assert rows[0]["city_key"] == "01"
    assert rows[0]["requests"] == 188
    assert unmapped == {"observed_ips": 1, "requests": 2}


def test_vietnam_country_contract_exposes_traffic_conservation():
    class Regions:
        def get(self, code):
            return {"country_code": code, "country_name": "Viet Nam", "market_score": 80}

    result = MapIntelligenceService(
        Regions(), clock=lambda: datetime(2026, 9, 1, tzinfo=timezone.utc),
        city_opportunities=lambda _code: [],
        city_state=lambda *_: {"coverage": {"total_ips": 3, "total_requests": 190}, "cities": [
            {"city_key": "hanoi", "city_name": "Hà Nội", "latitude": 21, "longitude": 105,
             "observed_ips": 2, "requests": 188},
            {"city_key": "unknown locality", "city_name": "Unknown locality", "observed_ips": 1, "requests": 2},
        ]},
    ).country("VN", "30d")
    assert result["cities"][0]["city_id"] == "01"
    assert result["coverage"]["unmapped_traffic"] == {"observed_ips": 1, "requests": 2}
    assert result["coverage"]["traffic_conservation"] is True


def test_world_contract_merges_opportunity_and_existing_threat_state():
    class Regions:
        def list(self, limit):
            assert limit == 1000
            return [
                {"country_code": "DE", "country_name": "Germany", "market_score": "82.4", "updated_at": "2026-08-31T18:00:00"},
                {"country_code": "US", "country_name": "United States", "market_score": None, "updated_at": ""},
            ]

    def threats(start, end):
        assert start.tzinfo and end.tzinfo
        return [{"country_code": "DE", "latitude": 51.16, "longitude": 10.45,
                 "critical_ips": 1, "medium_ips": 0, "low_ips": 0, "good_ips": 0, "unknown_ips": 2, "requests": 15,
                 "last_seen_at": datetime(2026, 9, 1, 1, 59, tzinfo=timezone.utc)}]

    result = MapIntelligenceService(Regions(), threats,
                                    lambda: datetime(2026, 9, 1, 2, tzinfo=timezone.utc)).world()
    assert result["generated_at"] == "2026-09-01T02:00:00Z"
    assert [item["country_code"] for item in result["countries"]] == ["DE", "US"]
    germany = result["countries"][0]
    assert germany["opportunity"] == {"score": 82.4, "updated_at": "2026-08-31T18:00:00Z"}
    assert germany["threat"] == {"critical_ips": 1, "medium_ips": 0, "low_ips": 0, "good_ips": 0, "unknown_ips": 2,
                                  "requests": 15, "flagged_ips": 1,
                                  "last_seen_at": "2026-09-01T01:59:00Z"}
    assert "threat_score" not in germany
    assert result["countries"][1]["opportunity"]["score"] is None


def test_unresolved_country_is_not_assigned_and_missing_threat_is_zero():
    class Regions:
        def list(self, limit):
            return [{"country_code": "DE", "country_name": "Germany", "market_score": 101,
                     "updated_at": "2026-09-01T00:00:00+07:00"}]

    result = MapIntelligenceService(Regions(), lambda *_: [{"country_code": None}],
                                    lambda: datetime(2026, 9, 1, tzinfo=timezone.utc)).world("1h")
    country = result["countries"][0]
    assert country["country_code"] == "DE"
    assert country["opportunity"]["score"] == 100.0
    assert country["threat"] == {"critical_ips": 0, "medium_ips": 0, "low_ips": 0, "good_ips": 0, "unknown_ips": 0,
                                  "requests": 0, "flagged_ips": 0, "last_seen_at": None}


def test_timestamp_normalization_is_utc():
    assert _utc_iso("2026-09-01T02:00:00+07:00") == "2026-08-31T19:00:00Z"


def test_world_accepts_custom_window():
    captured = {}

    class Regions:
        def list(self, limit):
            return []

    def threats(start, end):
        captured["window"] = (start, end)
        return []

    result = MapIntelligenceService(
        Regions(), threats, clock=lambda: datetime(2026, 9, 1, 2, tzinfo=timezone.utc)
    ).world(
        start=datetime(2026, 8, 31, 20, tzinfo=timezone.utc),
        end=datetime(2026, 9, 1, 1, tzinfo=timezone.utc),
    )
    assert result["range"] == "custom"
    assert captured["window"] == (
        datetime(2026, 8, 31, 20, tzinfo=timezone.utc),
        datetime(2026, 9, 1, 1, tzinfo=timezone.utc),
    )


def test_map_threat_contract_keeps_classified_ips_even_without_window_features():
    # Threat severity counts must be scoped to the selected feature window.
    source = Path("app/services/map_intelligence.py").read_text(encoding="utf-8")
    assert "LEFT JOIN (" in source
    assert source.count("f.ip IS NOT NULL AND COALESCE(cs.label, 'unknown')") == 3
    assert "OR COUNT(DISTINCT p.ip) FILTER" not in source
    assert "settings.DATASET_LIVE_ID" in source


def test_country_contract_keeps_city_score_null_and_tracks_coverage():
    class Regions:
        def get(self, code):
            return {"country_code": code, "country_name": "Germany", "market_score": 80.22}

    result = MapIntelligenceService(
        Regions(),
        clock=lambda: datetime(2026, 9, 1, 2, tzinfo=timezone.utc),
        city_opportunities=lambda _code: [{"city_id": "DE:CITY:BER", "city_name": "Berlin",
                                           "latitude": 52.52, "longitude": 13.405,
                                           "score": None, "raw_score": None, "percentile": None,
                                           "evidence_coverage": 0.83,
                                           "updated_at": "2026-08-31T18:00:00+00:00"}],
        city_state=lambda _code, _start, _end: {
            "coverage": {"located_ips": 3, "total_ips": 4, "city_coverage": .75,
                          "unlocated_ips": 1, "unlocated_requests": 7},
            "cities": [{"city_key": "berlin", "city_name": "Berlin", "latitude": 52.52,
                        "longitude": 13.405, "critical_ips": 2, "medium_ips": 1, "low_ips": 0, "good_ips": 0,
                        "requests": 48, "last_seen_at": "2026-09-01T01:59:00Z"}],
        },
    ).country("de")
    assert result["country"] == {"country_code": "DE", "country_name": "Germany", "opportunity_score": 80.22}
    assert result["coverage"]["city_coverage"] == .75
    city = result["cities"][0]
    assert city["opportunity"]["score"] is None
    assert city["threat"]["flagged_ips"] == 3
    assert city["threat"]["requests"] == 48


def test_country_omits_unresolved_city_without_coordinates():
    class Regions:
        def get(self, code): return {"country_code": code, "country_name": "Germany", "market_score": None}

    result = MapIntelligenceService(
        Regions(), clock=lambda: datetime(2026, 9, 1, tzinfo=timezone.utc),
        city_opportunities=lambda _code: [{"city_name": "Unknown", "score": 99, "latitude": None, "longitude": None}],
        city_state=lambda *_: {"coverage": {}, "cities": [{"city_key": "unknown", "city_name": "Unknown"}]},
    ).country("DE", "1h")
    assert result["cities"] == []
