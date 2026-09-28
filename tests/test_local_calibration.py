from scripts.geo.local_calibration import _select, _stability, _transform, run_calibration


def test_calibration_transforms_are_bounded_and_monotonic():
    values = [10.0, 20.0, 30.0, 40.0]
    for method in ("percentile", "robust_z"):
        result = _transform(values, method)
        assert result == sorted(result)
        assert all(0.0 <= value <= 1.0 for value in result)


def test_stability_is_deterministic():
    values = [float(value) for value in range(10, 110)]
    assert _stability(values, "percentile") == _stability(values, "percentile")


def test_selection_prefers_rank_stability_then_distortion():
    metrics = {
        "percentile": {"spearman_rank_correlation": .99, "p95_score_shift": .2, "median_absolute_score_shift": .1},
        "robust_z": {"spearman_rank_correlation": .98, "p95_score_shift": .01, "median_absolute_score_shift": .01},
    }
    assert _select(metrics) == "percentile"


def test_calibration_groups_tracks_independently_and_keeps_sparse_scores_unavailable():
    rows = [
        {"track": "woodworking", "raw_local_score": float(index)}
        for index in range(19)
    ] + [
        {"track": "metal_fabrication", "raw_local_score": float(index)}
        for index in range(20)
    ]

    class Repository:
        def list_calibration_candidates(self):
            return rows

        def update_local_calibration(self, updates):
            self.updates = updates
            return len(updates)

    repository = Repository()
    report = run_calibration(repository)

    assert report["groups"]["woodworking"]["selected_method"] is None
    assert report["groups"]["woodworking"]["status"] == "insufficient_stability"
    assert report["groups"]["metal_fabrication"]["selected_method"] in {"percentile", "robust_z"}
    wood_rows = [row for row in repository.updates if row["track"] == "woodworking"]
    assert len(wood_rows) == 19
    assert all(row["calibrated_score"] is None for row in wood_rows)
    assert report["updated"] == len(rows)
