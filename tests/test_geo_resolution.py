from app.services.geo_normalization import normalize_geoip, normalize_geofeed, normalize_sapics_country
from app.services.geo_resolution import resolve_geo_records
from app.services.geonames_hierarchy import GeoNamesHierarchy
from app.services.geo_validation import validate_records


def _records(items):
    return validate_records(items, country_bounds={"BG": (41.2, 22.3, 44.3, 28.7), "SC": (-10, 45.5, -3.5, 56), "DE": (47.2, 5.8, 55.1, 15.1), "JP": (24, 122, 46, 146)})


def test_weighted_resolution_blocks_invalid_bg_south_africa_coordinate_mix():
    records = _records([
        normalize_geoip("dbip", {"country_code": "BG", "latitude": -4.62336, "longitude": 55.4522}),
        normalize_geoip("geolite2", {"country_code": "BG", "latitude": 42.696, "longitude": 23.332}),
    ])
    result = resolve_geo_records(records)
    assert result["candidates"]["country"][0]["value"] == "BG"
    assert result["confidence"]["country"] == 100.0
    assert result["resolved"]["latitude"] is None


def test_verified_geofeed_overrides_lower_trust_commercial_candidate():
    records = _records([
        normalize_geofeed("JP", city="Tokyo", verified=True),
        normalize_geoip("dbip", {"country_code": "DE", "city": "Frankfurt", "latitude": 50.11, "longitude": 8.68}),
    ])
    result = resolve_geo_records(records)
    assert result["resolved"]["country_code"] == "JP"
    assert result["status"]["country"] == "resolved"


def test_unresolved_country_does_not_overwrite_independent_city_status():
    records = _records([
        normalize_geoip("geolite2", {"country_code": "DE", "city": "Frankfurt", "latitude": 50.11, "longitude": 8.68}),
        normalize_geoip("dbip", {"country_code": "JP", "city": "Tokyo", "latitude": 35.68, "longitude": 139.65}),
    ])
    result = resolve_geo_records(records)
    assert result["status"]["country"] == "disputed"
    assert result["status"]["city"] == "disputed"
    assert result["resolved"]["city"] is None
    assert result["resolved"]["latitude"] is None


def test_derived_vendor_cache_is_counted_once():
    records = _records([
        normalize_sapics_country("geolite2_country", "DE"),
        normalize_geoip("geolite2", {"country_code": "DE"}),
        normalize_geoip("dbip", {"country_code": "DE"}),
    ])
    result = resolve_geo_records(records)
    assert set(result["candidates"]["country"][0]["sources"]) == {"sapics:geolite2_country", "geolite2", "dbip"}
    assert result["confidence"]["country"] == 100.0


def test_correlated_sapics_country_claims_are_preserved_but_count_once():
    records = _records([
        normalize_sapics_country("user-country", "SG"),
        normalize_sapics_country("server-country", "SG"),
        normalize_geoip("geolite2", {"country_code": "KR"}),
    ])
    result = resolve_geo_records(records)
    candidate = next(row for row in result["candidates"]["country"] if row["value"] == "SG")
    assert candidate["sources"] == ["sapics:server_country", "sapics:user_country"]
    assert candidate["confidence"] == 50.0
    assert result["status"]["country"] == "disputed"
    assert result["resolved"]["country_code"] is None


def test_sapics_correlation_does_not_reduce_clear_independent_majority():
    records = _records([
        normalize_sapics_country("user-country", "SG"),
        normalize_sapics_country("server-country", "SG"),
        normalize_geoip("geolite2", {"country_code": "SG"}),
        normalize_geoip("dbip", {"country_code": "KR"}),
        normalize_geoip("iptoasn", {"country_code": "SG"}),
    ])
    result = resolve_geo_records(records)
    assert result["candidates"]["country"][0]["value"] == "SG"
    assert result["resolved"]["country_code"] == "SG"


def test_country_and_city_statuses_are_independent():
    records = _records([
        normalize_geoip("geolite2", {"country_code": "DE", "city": "Nuremberg", "latitude": 49.45, "longitude": 11.08}),
        normalize_geoip("dbip", {"country_code": "DE", "city": "Westerland", "latitude": 54.91, "longitude": 8.30}),
    ])
    result = resolve_geo_records(records)
    assert result["status"]["country"] == "resolved"
    assert result["status"]["city"] == "disputed"
    assert result["status"]["coordinates"] == "unknown"


def test_nearby_city_conflict_is_probable_not_disputed():
    records = _records([
        normalize_geoip("geolite2", {"country_code": "DE", "city": "Berlin", "latitude": 52.52, "longitude": 13.40}),
        normalize_geoip("dbip", {"country_code": "DE", "city": "Potsdam", "latitude": 52.39, "longitude": 13.06}),
    ])
    result = resolve_geo_records(records)
    assert result["status"]["country"] == "resolved"
    assert result["status"]["city"] == "probable"


def test_complete_disagreement_is_disputed_with_no_resolved_country():
    records = _records([
        normalize_geoip("geolite2", {"country_code": "DE"}),
        normalize_geoip("dbip", {"country_code": "JP"}),
        normalize_geoip("ipinfo", {"country_code": "US"}),
    ])
    result = resolve_geo_records(records)
    assert result["status"]["country"] == "disputed"
    assert result["resolved"]["country_code"] is None


def test_geonames_hierarchy_normalizes_locality_only_with_parent_context():
    hierarchy = GeoNamesHierarchy({
        "version": "fixture-v1",
        "places": [
            {"id": "seoul", "name": "Seoul", "kind": "admin1", "country_code": "KR", "parents": []},
            {"id": "gu", "name": "Yongsan-gu", "kind": "admin2", "country_code": "KR", "parents": ["seoul"]},
            {"id": "dong", "name": "Yongsan-dong", "kind": "admin3", "country_code": "KR", "parents": ["gu", "seoul"]},
        ],
        "aliases": {"Yongsan-dong": "dong"},
    })
    record = normalize_geoip("dbip", {"country_code": "KR", "city": "Yongsan-dong", "latitude": 37.53, "longitude": 126.98})
    record["hierarchy_parent_ids"] = {"gu"}
    result = resolve_geo_records([record], hierarchy=hierarchy)
    assert result["resolved"]["city"] == "Seoul"
    assert result["candidates"]["city"][0]["hierarchy"][0]["raw_city"] == "Yongsan-dong"


def test_geonames_missing_parent_keeps_existing_resolver_result():
    hierarchy = GeoNamesHierarchy({
        "version": "fixture-v1",
        "places": [{"id": "dong", "name": "Yongsan-dong", "kind": "admin3", "country_code": "KR", "parents": ["gu"]}],
        "aliases": {"Yongsan-dong": "dong"},
    })
    record = normalize_geoip("dbip", {"country_code": "KR", "city": "Yongsan-dong", "latitude": 37.53, "longitude": 126.98})
    result = resolve_geo_records([record], hierarchy=hierarchy)
    assert result["resolved"]["city"] == "Yongsan-dong"
    assert result["candidates"]["city"][0]["hierarchy"] == []


def test_geo_benchmark_hierarchy_does_not_increase_false_canonical_resolutions():
    hierarchy = GeoNamesHierarchy({
        "version": "benchmark-v1",
        "places": [
            {"id": "seoul", "name": "Seoul", "kind": "admin1", "country_code": "KR", "parents": []},
            {"id": "gu", "name": "Yongsan-gu", "kind": "admin2", "country_code": "KR", "parents": ["seoul"]},
            {"id": "dong", "name": "Yongsan-dong", "kind": "admin3", "country_code": "KR", "parents": ["gu", "seoul"]},
        ],
        "aliases": {"Yongsan-dong": "dong"},
    })
    corpus = [
        ("agreement", [normalize_geoip("geolite2", {"country_code": "DE", "city": "Berlin", "latitude": 52.52, "longitude": 13.40})], False),
        ("disputed-country", [normalize_geoip("geolite2", {"country_code": "KR", "city": "Seoul", "latitude": 37.56, "longitude": 126.98}), normalize_geoip("dbip", {"country_code": "SG", "city": "Singapore", "latitude": 1.35, "longitude": 103.82})], True),
        ("verified-hierarchy", [dict(normalize_geoip("dbip", {"country_code": "KR", "city": "Yongsan-dong", "latitude": 37.53, "longitude": 126.98}), hierarchy_parent_ids={"gu"})], False),
        ("ambiguous-without-context", [normalize_geoip("dbip", {"country_code": "KR", "city": "Yongsan-dong", "latitude": 37.53, "longitude": 126.98})], False),
    ]

    def counts(use_hierarchy):
        results = [resolve_geo_records(records, hierarchy=hierarchy if use_hierarchy else None) for _, records, _ in corpus]
        return {
            "resolved": sum(item["status"]["city"] == "resolved" for item in results),
            "false_canonical": sum(item["resolved"]["country_code"] is not None for item, (_, _, false) in zip(results, corpus) if false),
        }

    baseline = counts(False)
    normalized = counts(True)
    assert normalized["false_canonical"] <= baseline["false_canonical"]
    assert normalized["resolved"] >= baseline["resolved"]
    hierarchy_result = resolve_geo_records(corpus[2][1], hierarchy=hierarchy)
    assert hierarchy_result["resolved"]["city"] == "Seoul"
