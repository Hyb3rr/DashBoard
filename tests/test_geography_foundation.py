import pytest
from pathlib import Path
from urllib.error import HTTPError

from scripts.geo.geography_foundation import (
    assign_city_parents,
    choose_adaptive_level,
    normalize_boundaries,
    normalize_cities,
    persist_country,
    assign_boundary_parents,
    refresh_country,
    _mollweide_to_wgs84,
    _country_names,
)


def _boundary(name, source_id, coords):
    return {"type": "Feature", "id": source_id, "properties": {"boundaryName": name, "boundaryID": source_id},
            "geometry": {"type": "Polygon", "coordinates": [coords]}}


def test_normalize_and_parent_city_from_geojson():
    boundary = _boundary("North", "N", [[0, 0], [10, 0], [10, 10], [0, 10], [0, 0]])
    cities = normalize_cities({"type": "FeatureCollection", "features": [
        {"type": "Feature", "id": "CITY1", "properties": {"name": "Alpha"}, "geometry": {"type": "Point", "coordinates": [5, 5]}}
    ]}, "AA")
    adm1 = normalize_boundaries({"type": "FeatureCollection", "features": [boundary]}, "AA", 1)
    assign_city_parents(cities, adm1)
    assert cities[0]["parent_area_id"] == "AA:ADM1:N"
    assert adm1[0]["bbox_min_lat"] == 0
    assert adm1[0]["bbox_max_lon"] == 10


def test_adaptive_level_requires_coverage():
    boundary = _boundary("North", "N", [[0, 0], [10, 0], [10, 10], [0, 10], [0, 0]])
    adm2 = normalize_boundaries({"type": "FeatureCollection", "features": [boundary] * 5}, "AA", 2)
    cities = normalize_cities({"type": "FeatureCollection", "features": [
        {"type": "Feature", "id": "CITY1", "properties": {"name": "Alpha"}, "geometry": {"type": "Point", "coordinates": [5, 5]}},
        {"type": "Feature", "id": "CITY2", "properties": {"name": "Outside"}, "geometry": {"type": "Point", "coordinates": [50, 50]}},
    ]}, "AA")
    assert choose_adaptive_level(cities, [], adm2, min_adm2_city_coverage=.5) == 2
    assert choose_adaptive_level(cities, [], adm2, min_adm2_city_coverage=1.0) == 1


def test_missing_city_coordinates_are_not_fabricated():
    cities = normalize_cities({"type": "FeatureCollection", "features": [
        {"type": "Feature", "id": "NOPOINT", "properties": {"name": "Unknown"}, "geometry": None}
    ]}, "AA")
    assert cities == []


def test_persist_country_uses_existing_repository_contract(monkeypatch):
    class Repo:
        def __init__(self): self.areas = []; self.sources = []
        def upsert_areas(self, values): self.areas.extend(values); return len(values)
        def upsert_area_sources(self, values): self.sources.extend(values); return len(values)

    boundary = _boundary("North", "N", [[0, 0], [10, 0], [10, 10], [0, 10], [0, 0]])
    cities = normalize_cities({"type": "FeatureCollection", "features": [
        {"type": "Feature", "id": "CITY1", "properties": {"name": "Alpha"}, "geometry": {"type": "Point", "coordinates": [5, 5]}}
    ]}, "AA")
    adm1 = normalize_boundaries({"type": "FeatureCollection", "features": [boundary]}, "AA", 1)
    adm2 = normalize_boundaries({"type": "FeatureCollection", "features": [boundary] * 5}, "AA", 2)
    repo = Repo()
    result = persist_country(repo, "AA", cities, adm1, adm2)
    assert result["adaptive_admin_level"] == 2
    assert result["cities_with_parent"] == 1
    assert all("_feature" not in item for item in repo.areas)
    assert len(repo.sources) == len(repo.areas)
    admin_source_ids = {item["source_id"] for item in repo.areas if item["area_type"] == "administrative_area"}
    assert "ADM1:N" in admin_source_ids
    assert "ADM2:N" in admin_source_ids


def test_refresh_country_fetches_sources_and_records_job(monkeypatch):
    class Repo:
        def __init__(self): self.jobs = []; self.areas = []; self.sources = []
        def upsert_job_state(self, item): self.jobs.append(item); return item
        def upsert_areas(self, values): self.areas.extend(values); return len(values)
        def upsert_area_sources(self, values): self.sources.extend(values); return len(values)

    boundary = _boundary("North", "N", [[0, 0], [10, 0], [10, 10], [0, 10], [0, 0]])
    city_payload = {"type": "FeatureCollection", "features": [
        {"type": "Feature", "id": "CITY1", "properties": {"name": "Alpha"}, "geometry": {"type": "Point", "coordinates": [5, 5]}}
    ]}
    boundary_payload = {"type": "FeatureCollection", "features": [boundary]}
    metadata = {"buildDate": "test", "gjDownloadURL": "unused"}
    def fake_load(url, timeout=30):
        if "cities" in url:
            return city_payload
        return boundary_payload
    monkeypatch.setattr("scripts.geo.geography_foundation.load_json", fake_load)
    monkeypatch.setattr("scripts.geo.geography_foundation.geoboundaries_payload", lambda iso3, level, timeout=30: (boundary_payload, metadata))
    repo = Repo()
    cities = normalize_cities(city_payload, "AA")
    result = refresh_country(repo, "AA", "AAA", cities)
    assert result["country_code"] == "AA"
    assert repo.jobs[0]["status"] == "downloading"
    assert repo.jobs[-1]["status"] == "done"


def test_mollweide_inverse_uses_world_mollweide_scale():
    lat, lon = _mollweide_to_wgs84(984727.5438, 6132900.704)
    assert lat == pytest.approx(52.5688, abs=0.001)
    assert lon == pytest.approx(13.4275, abs=0.001)


def test_parent_assignment_prefilters_by_boundary_bbox():
    boundary = _boundary("North", "N", [[0, 0], [10, 0], [10, 10], [0, 10], [0, 0]])
    areas = normalize_boundaries({"type": "FeatureCollection", "features": [boundary]}, "AA", 2)
    cities = normalize_cities({"type": "FeatureCollection", "features": [
        {"type": "Feature", "id": "CITY1", "properties": {"name": "Alpha"},
         "geometry": {"type": "Point", "coordinates": [5, 5]}}
    ]}, "AA")
    assign_city_parents(cities, areas)
    assert cities[0]["parent_area_id"] == "AA:ADM2:N"


def test_adm2_boundaries_get_adm1_parent():
    parent = normalize_boundaries({"type": "FeatureCollection", "features": [_boundary("North", "N", [[0, 0], [10, 0], [10, 10], [0, 10], [0, 0]])]}, "AA", 1)
    child = normalize_boundaries({"type": "FeatureCollection", "features": [_boundary("District", "D", [[1, 1], [2, 1], [2, 2], [1, 2], [1, 1]])]}, "AA", 2)
    assign_boundary_parents(child, parent)
    assert child[0]["parent_area_id"] == "AA:ADM1:N"


def test_missing_adm2_uses_adm1(monkeypatch):
    class Repo:
        def __init__(self): self.jobs = []; self.areas = []; self.sources = []
        def upsert_job_state(self, item): self.jobs.append(item)
        def upsert_areas(self, values): self.areas.extend(values); return len(values)
        def upsert_area_sources(self, values): self.sources.extend(values); return len(values)

    boundary = _boundary("North", "N", [[0, 0], [10, 0], [10, 10], [0, 10], [0, 0]])
    payload = {"type": "FeatureCollection", "features": [boundary]}
    city = normalize_cities({"type": "FeatureCollection", "features": [
        {"type": "Feature", "id": "CITY1", "properties": {"name": "Alpha"},
         "geometry": {"type": "Point", "coordinates": [5, 5]}}
    ]}, "AA")

    def fake_boundaries(_iso3, level, _timeout=30):
        if level == 2:
            raise HTTPError("url", 404, "missing", {}, None)
        return payload, {"buildDate": "test"}

    monkeypatch.setattr("scripts.geo.geography_foundation.geoboundaries_payload", fake_boundaries)
    result = refresh_country(Repo(), "AA", "AAA", city)
    assert result["adaptive_admin_level"] == 1


def test_ghsl_country_name_aliases_cover_vietnam():
    assert "vietnam" in _country_names("VNM")


def test_refresh_all_resumes_done_countries(monkeypatch):
    class Repo:
        def get_job_state(self, job_key):
            return {"status": "done"} if job_key == "geography:DE" else None
        def upsert_job_state(self, item): return item
        def upsert_areas(self, values): return len(values)
        def upsert_area_sources(self, values): return len(values)

    monkeypatch.setattr("scripts.geo.geography_foundation._download_global_archive", lambda *args: Path("cached.zip"))
    monkeypatch.setattr("scripts.geo.geography_foundation._global_cities", lambda *args: [])
    monkeypatch.setattr("scripts.geo.geography_foundation.refresh_country", lambda *args: {"areas": 0})
    monkeypatch.setattr("scripts.geo.geography_foundation._boundary_artifacts_available", lambda *args: True)
    result = __import__("scripts.geo.geography_foundation", fromlist=["refresh_all"]).refresh_all(Repo(), "unused")
    assert result["skipped_done"] == 1


def test_refresh_all_rebuilds_done_country_when_boundary_artifact_is_missing(monkeypatch, tmp_path):
    class Repo:
        def get_job_state(self, job_key):
            return {"status": "done", "current_step": "adm2"} if job_key == "geography:AT" else None

    refreshed = []
    monkeypatch.setattr("scripts.geo.geography_foundation.catalog_rows", lambda: [
        {"country_code": "AT", "iso3_code": "AUT", "primary_market": True, "active": True},
    ])
    monkeypatch.setattr("scripts.geo.geography_foundation.GEOBOUNDARIES_CACHE_DIR", tmp_path)
    (tmp_path / "AUT").mkdir()
    (tmp_path / "AUT" / "ADM1.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr("scripts.geo.geography_foundation._download_global_archive", lambda *args: Path("cached.zip"))
    monkeypatch.setattr("scripts.geo.geography_foundation._global_cities", lambda *args: [])
    monkeypatch.setattr("scripts.geo.geography_foundation.refresh_country",
                        lambda _repo, country, *_args: refreshed.append(country) or {"areas": 0})
    result = __import__("scripts.geo.geography_foundation", fromlist=["refresh_all"]).refresh_all(Repo(), "unused")
    assert result["skipped_done"] == 0
    assert result["completed"] == 1
    assert refreshed == ["AT"]
