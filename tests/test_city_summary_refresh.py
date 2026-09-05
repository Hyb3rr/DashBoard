from scripts.geo.city_summary_refresh import build_city_summaries, calibrate_city_summaries


def _row(city, track, weight, score, cell):
    return {"snapshot_id":"s","country_code":"DE","city_id":city,"track":track,
            "h3_cell_id":cell,"membership_fraction":weight,"geometry_source":"ghsl_ucdb_r2024a",
            "evidence_status":"scored" if score is not None else "insufficient_local_evidence",
            "raw_local_score":score,"model_version":"phase6a-raw-v1"}


def test_city_score_is_membership_weighted_mean():
    result = build_city_summaries([_row("DE:CITY:1","woodworking",.25,20,"a"),
                                   _row("DE:CITY:1","woodworking",.75,40,"b")])[0]
    assert result["city_raw_score"] == 35
    assert result["membership_weight"] == 1
    assert result["scored_membership_weight"] == 1
    assert result["evidence_coverage"] == 1


def test_missing_membership_keeps_city_score_null():
    result = build_city_summaries([_row("DE:CITY:1","metal_fabrication",.5,None,"a")])[0]
    assert result["city_raw_score"] is None
    assert result["evidence_status"] == "insufficient_local_evidence"
    assert result["city_calibrated_score"] is None


def test_calibration_is_separate_per_track():
    rows = [build_city_summaries([_row("DE:CITY:1","woodworking",1,10,"a")])[0],
            build_city_summaries([_row("DE:CITY:2","woodworking",1,20,"b")])[0],
            build_city_summaries([_row("DE:CITY:3","metal_fabrication",1,100,"c")])[0]]
    result = calibrate_city_summaries(rows)
    by_city = {row["city_id"]: row for row in result}
    assert by_city["DE:CITY:1"]["city_percentile"] == .25
    assert by_city["DE:CITY:2"]["city_percentile"] == .75
    assert by_city["DE:CITY:3"]["city_percentile"] == .5
