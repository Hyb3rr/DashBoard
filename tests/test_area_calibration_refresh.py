from scripts.geo.area_calibration_refresh import AREA_CALIBRATION_VERSION, calibrate_area_summaries


def _row(area, score, track="woodworking"):
    return {"snapshot_id": "s", "country_code": "DE", "h3_resolution": 7,
            "area_id": area, "track": track, "area_type": "administrative_area",
            "area_raw_score": score, "evidence_status": "scored"}


def test_calibration_is_per_track_and_preserves_raw_score():
    rows = [_row("A", 10), _row("B", 20), _row("C", 30), _row("D", 100, "metal_fabrication")]
    result = calibrate_area_summaries(rows)
    by_area = {row["area_id"]: row for row in result}
    assert by_area["A"]["area_raw_score"] == 10
    assert by_area["A"]["area_percentile"] == .166667
    assert by_area["C"]["area_percentile"] == .833333
    assert by_area["D"]["area_percentile"] == .5
    assert all(row["calibration_version"] == AREA_CALIBRATION_VERSION for row in result)


def test_missing_raw_score_is_not_calibrated():
    assert calibrate_area_summaries([_row("A", None)]) == []
