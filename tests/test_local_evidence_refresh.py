from scripts.geo.local_evidence_refresh import (
    AUXILIARY_VERSION,
    _count_auxiliary_tags,
    _empty_counts,
    _project_auxiliary_rows,
    refresh_local_evidence,
)


def test_auxiliary_tag_rules_keep_industrial_and_access_counts_independent():
    counts = _empty_counts()

    _count_auxiliary_tags({
        "landuse": "industrial",
        "industrial": "port",
        "highway": "trunk",
        "railway": "rail",
        "natural": "harbour",
        "aeroway": "terminal",
    }, counts)

    assert counts == {
        "industrial_land_count": 1,
        "motorway_count": 1,
        "primary_road_count": 0,
        "railway_count": 1,
        "port_count": 1,
        "airport_count": 1,
        "access_observation_count": 4,
    }


def test_auxiliary_projection_keeps_both_tracks_and_provenance():
    rows = _project_auxiliary_rows({"cell-1": _empty_counts()}, "VN", 7, "a" * 64)

    assert [row["track"] for row in rows] == ["woodworking", "metal_fabrication"]
    assert all(row["source_version"] == AUXILIARY_VERSION for row in rows)
    assert all(row["source_hash"] == "a" * 64 for row in rows)


def test_rerun_skips_from_persisted_provenance_when_source_cache_is_evicted(monkeypatch, tmp_path):
    country = "AT"
    source_hash = "a" * 64

    class Repo:
        def active_osm_snapshot(self, code):
            assert code == country
            return {"snapshot_id": "osm:AT:snapshot", "source_hash": source_hash, "active": True}

        def get_job_state(self, key):
            assert key == "osm_aux:AT"
            return {"status": "done", "source_hash": source_hash}

        def upsert_job_state(self, _item):
            raise AssertionError("idempotent rerun must not mutate job state")

    monkeypatch.setenv("OSM_CACHE_DIR", str(tmp_path))
    monkeypatch.setenv("OSM_COUNTRIES", country)
    monkeypatch.setattr("scripts.geo.local_evidence_refresh.resolve_source",
                        lambda *_args: (_ for _ in ()).throw(AssertionError("source must not be resolved")))
    result = refresh_local_evidence(Repo(), [country])
    assert result == {
        "status": "completed",
        "countries": {country: {"status": "skipped_unchanged", "source_hash": source_hash}},
        "failed": [],
    }
