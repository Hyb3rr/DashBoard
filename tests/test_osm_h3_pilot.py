from pathlib import Path
import inspect

from app.config.market_sources import UNSUPPORTED_OSM_COUNTRIES, WAVE_1_COUNTRIES, resolve_osm_source
from app.db.market_repository import MarketRepository
from scripts.geo.osm_h3_pilot import (
    CLASSIFICATION_VERSION, FILTER_VERSION, PRIORITY_COUNTRIES, PilotMetrics, _entity_points,
    classify_tags, download_snapshot, native_filter_args, percentile, persist_report, preflight_osm_source,
    preflight_osm_sources, refresh_osm_pilot, safe_snapshot_activation,
    apply_cache_retention, cache_retention_plan,
)


def test_download_snapshot_resumes_partial_with_http_range(monkeypatch, tmp_path):
    destination = tmp_path / "fr.osm.pbf"
    partial = destination.with_suffix(destination.suffix + ".part")
    partial.write_bytes(b"old-")

    class Response:
        status_code = 206
        headers = {"Content-Range": "bytes 4-10/11"}

        def __enter__(self): return self
        def __exit__(self, *_args): return False
        def raise_for_status(self): pass
        def iter_content(self, chunk_size):
            assert chunk_size == 1024 * 1024
            yield b"content"

    def get(_url, **kwargs):
        assert kwargs["headers"]["Range"] == "bytes=4-"
        return Response()

    monkeypatch.setattr("scripts.geo.osm_h3_pilot.requests.get", get)
    path, written = download_snapshot("https://example.test/fr.pbf", destination)
    assert path == destination
    assert written == len(b"content")
    assert destination.read_bytes() == b"old-content"
    assert not partial.exists()


def test_download_snapshot_restarts_safely_when_range_is_unsupported(monkeypatch, tmp_path):
    destination = tmp_path / "source.osm.pbf"
    partial = destination.with_suffix(destination.suffix + ".part")
    partial.write_bytes(b"stale")

    class Response:
        status_code = 200
        headers = {}

        def __enter__(self): return self
        def __exit__(self, *_args): return False
        def raise_for_status(self): pass
        def iter_content(self, chunk_size): yield b"fresh"

    def get(_url, **kwargs):
        assert kwargs["headers"]["Range"] == "bytes=5-"
        return Response()

    monkeypatch.setattr("scripts.geo.osm_h3_pilot.requests.get", get)
    path, written = download_snapshot("https://example.test/source.pbf", destination)
    assert path == destination
    assert written == len(b"fresh")
    assert destination.read_bytes() == b"fresh"
    assert not partial.exists()


def test_tag_filter_keeps_sectors_separate():
    assert classify_tags({"craft": "carpenter"}) == {"WOODWORKING"}
    assert classify_tags({"industrial": "metalworking"}) == {"METAL_FABRICATION"}
    assert classify_tags({"amenity": "school"}) == set()


def test_metrics_report_rejection_rate():
    metrics = PilotMetrics("SG", str(Path("sg.osm.pbf")), candidates_seen=10, rejected_by_tag=7)
    assert metrics.rejection_rate == 0.7
    assert metrics.as_dict()["rejection_rate"] == 0.7


def test_failed_snapshot_keeps_previous_active():
    old = {"A": "hash-a", "B": "hash-b"}
    new = {"A": "hash-a2", "D": "hash-d"}
    assert safe_snapshot_activation(old, new, failed=True) == old
    assert safe_snapshot_activation(old, new) == new


def test_native_filter_is_versioned_and_matches_classification_rules():
    filters = set(native_filter_args())
    assert FILTER_VERSION == "phase4a-sector-tags-v1"
    assert "nwr/craft=carpenter" in filters
    assert "nwr/industrial=metalworking" in filters
    assert "nwr/amenity=school" not in filters


def test_retained_way_keeps_referenced_geometry():
    class Location:
        def __init__(self, lat, lon):
            self.lat, self.lon = lat, lon

        def valid(self):
            return True

    class Node:
        def __init__(self, lat, lon):
            self.location = Location(lat, lon)

    class Way:
        nodes = (Node(10.0, 106.0), Node(10.2, 106.2))

    assert _entity_points(Way()) == [(10.1, 106.1)]


def test_persist_report_keeps_raw_tracks_and_res7(monkeypatch):
    monkeypatch.setenv("MARKET_H3_RESOLUTION", "7")

    class Repo:
        def __init__(self):
            self.snapshots, self.features, self.cells = [], [], []

        def upsert_osm_snapshot(self, item):
            self.snapshots.append(item)
            return item

        def upsert_cell_features(self, items):
            self.features.extend(items)
            return len(items)

        def upsert_opportunity_cells(self, items):
            self.cells.extend(items)
            return len(items)

        def activate_osm_snapshot(self, country, snapshot_id):
            return {"country_code": country, "snapshot_id": snapshot_id, "status": "active"}

    repo = Repo()
    result = persist_report(repo, {
        "country": "VN", "source_hash": "a" * 64,
        "cell_features": {
            "7|8928308280fffff|woodworking": {"osm_feature_count": 2, "wood_processing_count": 2},
            "7|8928308280fffff|metal_fabrication": {"osm_feature_count": 1, "metal_evidence_count": 1},
        },
    }, "https://example/pbf", "2026-08-25")
    assert result["status"] == "active"
    assert {row["track"] for row in repo.features} == {"woodworking", "metal_fabrication"}
    assert repo.snapshots[0]["h3_resolution"] == 7
    assert repo.snapshots[0]["classification_version"] == CLASSIFICATION_VERSION


def test_scheduler_refresh_is_country_isolated_and_marks_job_failure(monkeypatch, tmp_path):
    monkeypatch.setenv("OSM_COUNTRIES", "SG,VN,DE")
    monkeypatch.setenv("OSM_PBF_PATH_SG", str(tmp_path / "sg.pbf"))
    monkeypatch.setenv("OSM_PBF_PATH_VN", str(tmp_path / "vn.pbf"))
    monkeypatch.setenv("OSM_PBF_PATH_DE", str(tmp_path / "de.pbf"))
    def download(_url, destination, _timeout):
        destination.write_bytes(b"pbf")
        return destination, 3
    monkeypatch.setattr("scripts.geo.osm_h3_pilot.download_snapshot", download)
    monkeypatch.setattr("scripts.geo.osm_h3_pilot.source_size", lambda *_args: 3)
    monkeypatch.setattr("scripts.geo.osm_h3_pilot.run_native_pipeline", lambda path, country, *args: (_ for _ in ()).throw(RuntimeError("DE failure")) if country == "DE" else {"country": country, "source_hash": "a" * 64, "cell_features": {}})

    class Repo:
        def __init__(self): self.jobs = {}; self.active = {}
        def upsert_job_state(self, item): self.jobs[item["job_key"]] = item; return item
        def get_job_state(self, key): return self.jobs.get(key)
        def active_osm_snapshot(self, country): return self.active.get(country)

    def persist(repo, report, _url, _version):
        snapshot = {"status": "active", "snapshot_id": report["country"], "source_hash": report["source_hash"]}
        repo.active[report["country"]] = snapshot
        return snapshot
    monkeypatch.setattr("scripts.geo.osm_h3_pilot.persist_report", persist)

    result = refresh_osm_pilot(Repo())
    assert result["status"] == "partial"
    assert result["countries"]["SG"]["status"] == "updated"
    assert result["countries"]["VN"]["status"] == "updated"
    assert result["countries"]["DE"]["status"] == "failed"


def test_scale_benchmark_percentiles():
    assert percentile([3.0, 1.0, 2.0], 0.5) == 2.0
    assert percentile([], 0.95) is None


def test_priority_v1_is_generic_benchmark_scope():
    assert PRIORITY_COUNTRIES == ("SG", "VN", "DE", "TH", "MY", "ID", "PH", "KR", "PL", "IT")


def test_wave1_registry_resolves_all_countries_without_fallback():
    for country in WAVE_1_COUNTRIES:
        if country in UNSUPPORTED_OSM_COUNTRIES:
            continue
        url, source_kind = resolve_osm_source(country, {})
        assert url.startswith("https://download.geofabrik.de/")
        assert source_kind == "geofabrik_registry"


def test_unregistered_source_is_an_explicit_config_error():
    try:
        resolve_osm_source("XX", {})
    except ValueError as exc:
        assert "not registered" in str(exc)
    else:
        raise AssertionError("unregistered country unexpectedly resolved")


def test_unsupported_country_does_not_use_regional_fallback():
    try:
        resolve_osm_source("SA", {})
    except ValueError as exc:
        assert "explicitly unsupported" in str(exc)
        assert "country-scoped" in str(exc)
    else:
        raise AssertionError("Saudi Arabia unexpectedly resolved to a mixed-country source")


def test_expansion_sources_are_explicit_country_scoped_urls():
    for country in ("AD", "AF", "AL"):
        url, source_kind = resolve_osm_source(country, {})
        assert country.lower() in url
        assert source_kind == "geofabrik_registry"


def test_cell_feature_persistence_has_one_placeholder_per_field():
    source = inspect.getsource(MarketRepository.upsert_cell_features)
    values_sql = source.split("VALUES (", 1)[1].split(")", 1)[0]
    assert values_sql.count("%s") == 18


def test_source_preflight_is_read_only_and_reports_disk_guard(monkeypatch, tmp_path):
    monkeypatch.setattr("scripts.geo.osm_h3_pilot.source_size", lambda *_args: 123)
    monkeypatch.setenv("OSM_CACHE_SOFT_LIMIT_GIB", "0")
    result = preflight_osm_source("IN", tmp_path)
    assert result["source_resolved"] is True
    assert result["content_length_bytes"] == 123
    assert result["disk_before_bytes"] == 0
    assert result["estimated_download_bytes"] == 123
    assert result["retention_action"] == "cleanup_candidates_and_superseded_sources_before_download"
    assert list(tmp_path.iterdir()) == []


def test_source_preflight_reports_all_countries_and_blocks_hard_limit(monkeypatch, tmp_path):
    monkeypatch.setattr("scripts.geo.osm_h3_pilot.source_size", lambda *_args: 2)
    monkeypatch.setattr("scripts.geo.osm_h3_pilot.cache_bytes", lambda _path: 10 * 1024 ** 3)
    result = preflight_osm_sources(("IN", "XX"), tmp_path)
    assert result["status"] == "blocked"
    assert result["countries"]["IN"]["status"] == "blocked_disk_hard_limit"
    assert result["countries"]["XX"]["status"] == "blocked_source"


def test_cache_retention_selects_only_verified_idle_sources_and_candidates(tmp_path):
    source_dir = tmp_path / "sources"
    candidate_dir = tmp_path / "candidates"
    source_dir.mkdir()
    candidate_dir.mkdir()
    (source_dir / "aa.osm.pbf").write_bytes(b"a" * 7)
    (source_dir / "bb.osm.pbf").write_bytes(b"b" * 5)
    (source_dir / "cc.osm.pbf").write_bytes(b"c" * 3)
    (source_dir / "dd.osm.pbf.part").write_bytes(b"d" * 11)
    (candidate_dir / "old.osm.pbf").write_bytes(b"x" * 2)
    plan = cache_retention_plan(tmp_path, ("AA", "BB"), ("BB",), target_bytes=21)
    assert plan["status"] == "ready"
    assert [item["path"] for item in plan["deletions"]] == ["sources/aa.osm.pbf"]
    protected = {item["path"]: item["reason"] for item in plan["protected"]}
    assert protected["sources/bb.osm.pbf"] == "source_in_use"
    assert protected["sources/cc.osm.pbf"] == "no_verified_active_snapshot"
    assert protected["sources/dd.osm.pbf.part"] == "incomplete_or_lock_file"


def test_cache_retention_apply_is_exact_and_idempotent(tmp_path):
    source_dir = tmp_path / "sources"
    source_dir.mkdir()
    path = source_dir / "aa.osm.pbf"
    path.write_bytes(b"a" * 7)
    plan = cache_retention_plan(tmp_path, ("AA",), target_bytes=0)
    assert apply_cache_retention(plan)["status"] == "applied"
    assert not path.exists()
    second = cache_retention_plan(tmp_path, ("AA",), target_bytes=0)
    assert second["deletions"] == []
