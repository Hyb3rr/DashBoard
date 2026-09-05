from scripts.geo.local_opportunity_refresh import RAW_MODEL_VERSION, build_local_rows


def _input(track="woodworking"):
    return {"snapshot_id": "osm:DE:test:r7", "h3_cell_id": "8928308280fffff", "h3_resolution": 7,
            "track": track, "osm_feature_count": 4, "industrial_land_count": 2,
            "access_observation_count": 3}


def test_strong_evidence_scores_and_explains_components():
    row = build_local_rows("DE", 80.0, [_input()])[0]
    assert row["evidence_status"] == "scored"
    assert row["raw_local_score"] is not None
    assert row["model_version"] == RAW_MODEL_VERSION
    assert "formula" in row["evidence_components"]


def test_missing_evidence_never_becomes_zero():
    item = {**_input(), "osm_feature_count": 0, "industrial_land_count": 0, "access_observation_count": 0}
    row = build_local_rows("DE", 80.0, [item])[0]
    assert row["evidence_status"] == "insufficient_local_evidence"
    assert row["raw_local_score"] is None


def test_tracks_remain_separate():
    rows = build_local_rows("DE", 80.0, [_input("woodworking"), _input("metal_fabrication")])
    assert {row["track"] for row in rows} == {"woodworking", "metal_fabrication"}
