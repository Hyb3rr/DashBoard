import pytest

from app.core import enrichment


@pytest.mark.asyncio
async def test_enrichment_pipeline_drops_cross_country_coordinate_candidate(monkeypatch):
    countries = {name: "BG" for name in ("user_country", "server_country", "geolite2_country", "dbip_country", "iptoasn_country")}
    cities = {
        "geolite2_city": {"country_code": "BG", "city": None, "latitude": 42.696, "longitude": 23.332},
        "dbip_city": {"country_code": "BG", "city": None, "latitude": -4.62336, "longitude": 55.4522},
    }
    monkeypatch.setattr(enrichment, "_local_intelligence", lambda ip: ({}, {}, {}, []))
    monkeypatch.setattr(enrichment, "bounds_for", lambda codes: {"BG": (41.0, 22.0, 44.2, 28.7)} if "BG" in codes else {})
    monkeypatch.setattr(enrichment, "resolve_network_location", lambda *args, **kwargs: {
        "country": "Bulgaria", "country_code": "BG", "sources": [], "confidence": 0,
        "registration": {"country_code": "BG", "source": "rir:ripe"},
    })
    monkeypatch.setattr("app.services.sapics_reader.lookup", lambda ip: {
        "country": {"candidates": countries},
        "city": {"candidates": cities},
        "asn": {"number": 209101, "organization": "IP Vendetta Inc."},
        "infrastructure": {},
    })
    monkeypatch.setattr("app.services.ip2region_reader.lookup", lambda ip: {"city": "Frankfurt", "region": "Hesse", "country_code": "DE"})

    result = await enrichment.lookup("45.149.156.160")
    location = result["network_location"]

    assert location["canonical_resolution"]["resolved"]["country_code"] == "BG"
    assert location["canonical_resolution"]["resolved"]["city"] is None
    assert location["canonical_resolution"]["resolved"]["latitude"] is None
    assert location["canonical_resolution"]["resolved"]["longitude"] is None
    assert location["canonical_resolution"]["status"]["coordinates"] == "unknown"
    assert any(item.get("excluded_reason") == "coordinate_country_mismatch" for item in location["canonical_resolution"]["candidates"]["country"])


@pytest.mark.asyncio
async def test_shared_vietnam_parent_does_not_become_city_conflict_downstream(monkeypatch):
    countries = {"geolite2_country": "VN", "dbip_country": "VN"}
    cities = {
        "geolite2_city": {
            "country_code": "VN", "city": "Ho Chi Minh City", "state": "Ho Chi Minh",
            "latitude": 10.7769, "longitude": 106.7009,
        },
        "dbip_city": {
            "country_code": "VN", "city": "Ho Chi Minh City", "raw_city": "Quan Tan Phu",
            "state": "Ho Chi Minh City (HCMC)", "latitude": 10.80, "longitude": 106.72,
        },
    }
    monkeypatch.setattr(enrichment, "_local_intelligence", lambda ip: ({}, {}, {}, []))
    monkeypatch.setattr(enrichment, "bounds_for", lambda codes: {"VN": (8.0, 102.0, 24.0, 110.0)})
    monkeypatch.setattr(enrichment, "resolve_network_location", lambda *args, **kwargs: {
        "country": "Vietnam", "country_code": "VN", "sources": [], "confidence": 0,
    })
    monkeypatch.setattr("app.services.sapics_reader.lookup", lambda ip: {
        "country": {"candidates": countries, "value": "VN", "conflict": False},
        "city": {
            "candidates": cities, "value": "Ho Chi Minh City", "source": "geolite2_city",
            "conflict": False, "same_vietnam_parent": True, "coordinate_conflict": False,
            "status": "resolved",
        },
        "asn": {}, "infrastructure": {},
    })
    monkeypatch.setattr("app.services.ip2region_reader.lookup", lambda ip: {})

    result = await enrichment.lookup("1.1.1.1")

    assert result["city"] == "Ho Chi Minh City"
    assert result["network_location"]["city_conflict"] is False
    assert result["network_location"]["city_status"] != "disputed"
