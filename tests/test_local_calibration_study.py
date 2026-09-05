from scripts.geo.local_calibration_study import candidate_calibrations, run_study, summarize


def test_summary_reports_distribution_without_mutation():
    result = summarize([1, 2, 3, 4, 5])
    assert result["count"] == 5
    assert result["median"] == 3
    assert result["iqr"] == 2
    assert result["p5"] == 1.2
    assert result["p95"] == 4.8
    assert result["lower_fence"] == -1.0
    assert result["upper_fence"] == 7.0
    assert result["outlier_count_low"] == 0
    assert result["outlier_count_high"] == 0
    assert result["outlier_percentage"] == 0.0


def test_candidate_calibrations_are_comparable_but_not_selected():
    result = candidate_calibrations([10, 20, 30, 40, 50])
    assert set(result) == {"percentile", "robust_quantile", "robust_z"}
    assert all(len(values) == 5 for values in result.values())


def test_study_groups_track_and_area_type():
    class Repo:
        def list_raw_local_scores(self):
            return [{"country_code": "DE", "track": "woodworking", "area_type": "city", "raw_local_score": 10},
                    {"country_code": "DE", "track": "woodworking", "area_type": "city", "raw_local_score": 20}]

    result = run_study(Repo(), ["DE"])
    assert result["total_scored"] == 2
    assert result["groups"]["woodworking:city"]["median"] == 15
    assert result["study_version"] == "phase6b-study-v2"
