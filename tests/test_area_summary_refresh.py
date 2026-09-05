from scripts.geo.area_summary_refresh import build_area_summaries


def _row(area, track, score, status="scored", cell="cell"):
    return {
        "snapshot_id": "snap-1", "country_code": "DE", "area_id": area,
        "h3_resolution": 7, "track": track, "h3_cell_id": cell,
        "raw_local_score": score, "evidence_status": status,
        "model_version": "phase6a-raw-v1", "calibration_version": None,
    }


def test_area_score_uses_scored_mean_and_separate_coverage():
    summaries, counts = build_area_summaries([
        _row("DE:ADM1:A", "woodworking", 20, cell="a"),
        _row("DE:ADM1:A", "woodworking", 40, cell="b"),
        _row("DE:ADM1:A", "woodworking", None, "insufficient_local_evidence", "c"),
    ])
    assert counts == {"input_rows": 3, "unmapped_rows": 0}
    assert len(summaries) == 1
    assert summaries[0]["total_cells"] == 3
    assert summaries[0]["scored_cells"] == 2
    assert summaries[0]["evidence_coverage"] == 2 / 3
    assert summaries[0]["area_raw_score"] == 30


def test_all_missing_cells_keep_null_score():
    summaries, _ = build_area_summaries([
        _row("DE:ADM1:A", "metal_fabrication", None, "insufficient_local_evidence", "a"),
        _row("DE:ADM1:A", "metal_fabrication", None, "insufficient_local_evidence", "b"),
    ])
    assert summaries[0]["evidence_status"] == "insufficient_local_evidence"
    assert summaries[0]["missing_reason"] == "insufficient_local_evidence"
    assert summaries[0]["area_raw_score"] is None
    assert summaries[0]["evidence_coverage"] == 0


def test_unmapped_cells_are_not_assigned_or_summarized():
    summaries, counts = build_area_summaries([
        _row(None, "woodworking", 99, cell="unmapped"),
        _row("DE:ADM1:A", "woodworking", 50, cell="mapped"),
    ])
    assert counts["unmapped_rows"] == 1
    assert len(summaries) == 1
    assert summaries[0]["area_id"] == "DE:ADM1:A"


def test_same_input_is_deterministic_for_idempotent_upsert():
    rows = [_row("DE:ADM1:B", "metal_fabrication", 11, cell="b"),
            _row("DE:ADM1:A", "metal_fabrication", 22, cell="a")]
    first, _ = build_area_summaries(rows)
    second, _ = build_area_summaries(rows)
    assert first == second
