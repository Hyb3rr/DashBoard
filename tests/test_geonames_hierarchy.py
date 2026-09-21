import json
from pathlib import Path

from app.services.geonames_hierarchy import GeoNamesHierarchy


def _index():
    return GeoNamesHierarchy({
        "version": "geonames-2026-09-12-fixture",
        "places": [
            {"id": "kr", "name": "South Korea", "kind": "country", "country_code": "KR", "parents": []},
            {"id": "seoul", "name": "Seoul", "kind": "admin1", "country_code": "KR", "parents": ["kr"]},
            {"id": "yongsan-gu", "name": "Yongsan-gu", "kind": "admin2", "country_code": "KR", "parents": ["seoul", "kr"]},
            {"id": "yongsan-dong", "name": "Yongsan-dong", "kind": "locality", "country_code": "KR", "parents": ["yongsan-gu", "seoul", "kr"]},
            {"id": "other-yongsan", "name": "Yongsan-dong", "kind": "locality", "country_code": "KR", "parents": ["kr"]},
        ],
        "aliases": {"Seoul": "seoul", "Yongsan-dong": "yongsan-dong", "Yongsan-gu": "yongsan-gu"},
    })


def test_locality_resolves_only_with_explicit_parent_context():
    index = _index()
    place = index.resolve("Yongsan-dong", country_code="KR", parent_ids={"yongsan-gu"})
    assert place["id"] == "yongsan-dong"
    assert "seoul" in place["parents"]


def test_same_name_without_parent_context_is_not_inferred():
    index = GeoNamesHierarchy({
        "version": "fixture",
        "places": [
            {"id": "a", "name": "Yongsan-dong", "kind": "locality", "country_code": "KR", "parents": ["seoul"]},
            {"id": "b", "name": "Yongsan-dong", "kind": "locality", "country_code": "KR", "parents": ["other"]},
            {"id": "c", "name": "Yongsan-dong", "kind": "locality", "country_code": "JP", "parents": ["tokyo"]},
        ],
        "aliases": {"Yongsan-dong": ["a", "b", "c"]},
    })
    assert index.resolve("Yongsan-dong") is None
    assert index.resolve("Yongsan-dong", country_code="KR") is None
    assert index.resolve("Yongsan-dong", country_code="KR", parent_ids={"unknown"}) is None
    assert index.resolve("Yongsan-dong", country_code="KR", parent_ids={"seoul"})["id"] == "a"
    assert index.resolve("Yongsan-dong", country_code="KR", parent_ids={"wrong"}) is None


def test_index_round_trips_from_local_json(tmp_path):
    payload = {"version": "v1", "places": [{"id": "seoul", "name": "Seoul", "parents": []}], "aliases": {"Seoul": "seoul"}}
    path = tmp_path / "index.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert GeoNamesHierarchy.from_path(path).resolve("Seoul")["id"] == "seoul"


def test_versioned_kr_snapshot_proves_yongsan_dong_seoul_hierarchy():
    path = Path(__file__).parent / "fixtures" / "geo" / "geonames" / "kr-seoul-hierarchy.json"
    index = GeoNamesHierarchy.from_path(path)
    place = index.resolve("Yongsan-dong", country_code="KR", parent_ids={"1832311"})
    assert place["id"] == "8692870"
    assert "1835847" in place["parents"]
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["source_files"] == ["KR.zip", "hierarchy.zip"]
    assert len(payload["generated_payload_sha256"]) == 64
