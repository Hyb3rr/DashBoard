from scripts.geo.local_evidence_refresh import refresh_local_evidence


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
