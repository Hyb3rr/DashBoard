import pandas as pd
from datetime import datetime, timezone

from app.ai import detector


def _frame(rows=12, ips=("203.0.113.1", "203.0.113.2", "203.0.113.3")):
    """Create deterministic sample model windows for resource-bound tests."""
    return pd.DataFrame(
        [
            {"ip": ip, "window_start": pd.Timestamp("2026-09-18T00:00Z") + pd.Timedelta(minutes=index), "requests": index}
            for index, ip in enumerate((ips * rows)[:rows])
        ]
    )


def test_training_bound_is_deterministic_and_preserves_multiple_ips(monkeypatch):
    """Select the same bounded IP/window cohort regardless of input row order."""
    monkeypatch.setenv("AI_TRAIN_MAX_IPS", "2")
    monkeypatch.setenv("AI_TRAIN_MAX_WINDOWS", "4")
    frame = _frame()
    first, first_meta = detector._bound_training_frame(frame)
    second, second_meta = detector._bound_training_frame(frame.sample(frac=1, random_state=7))

    assert len(first) == 4
    assert first["ip"].nunique() == 2
    assert first[["ip", "window_start"]].to_dict("records") == second[["ip", "window_start"]].to_dict("records")
    assert first_meta == second_meta
    assert first_meta["training_input_bounded"] is True


def test_training_bounds_do_not_change_small_input(monkeypatch):
    """Leave datasets below configured training limits unchanged."""
    monkeypatch.setenv("AI_TRAIN_MAX_IPS", "10")
    monkeypatch.setenv("AI_TRAIN_MAX_WINDOWS", "100")
    frame = _frame(6, ("203.0.113.1", "203.0.113.2"))
    bounded, metadata = detector._bound_training_frame(frame)
    assert len(bounded) == len(frame)
    assert bounded["ip"].nunique() == 2
    assert metadata["training_input_bounded"] is False


def test_fit_model_uses_controlled_worker_count(monkeypatch):
    """Pass the configured worker limit into the fitted Isolation Forest."""
    monkeypatch.setenv("AI_TRAIN_N_JOBS", "1")
    frame = _frame(60, ("203.0.113.1", "203.0.113.2", "203.0.113.3"))
    for column in detector.FEATURE_COLUMNS:
        frame[column] = 1.0
    bundle = detector._fit_model_frame(frame, {"model_version": "test", "trained_at": "now", "training_start": "start", "training_end": "end"})
    assert bundle["training_windows"] == 60
    assert bundle["training_input_bounded"] is False


def test_training_source_query_is_bounded_before_fetchall(monkeypatch):
    """Apply deterministic row and IP limits in SQL before fetching training data."""
    class Result:
        def fetchall(self):
            """Return an empty result set for the SQL contract test."""
            return []

    class Connection:
        def __init__(self):
            """Initialize captured SQL state for the repository-like fake."""
            self.sql = ""
            self.params = None

        def execute(self, sql, params):
            """Capture the bounded feature query and return its fake result."""
            self.sql = sql
            self.params = params
            return Result()

    monkeypatch.setenv("AI_TRAIN_MAX_IPS", "7")
    monkeypatch.setenv("AI_TRAIN_MAX_WINDOWS", "11")
    connection = Connection()
    frame = detector._feature_frame(
        connection,
        datetime(2026, 9, 18, tzinfo=timezone.utc),
        datetime(2026, 9, 19, tzinfo=timezone.utc),
    )

    assert frame.empty
    assert "selected_ips" in connection.sql
    assert "row_number() OVER" in connection.sql
    assert "LIMIT %s" in connection.sql
    assert connection.params[-1] == 11


def test_score_windows_returns_scored_copy_and_anomaly_count():
    """Score each window without mutating the source frame or losing anomaly count."""
    import numpy as np

    class Scaler:
        def transform(self, values):
            """Pass through feature values for deterministic scoring assertions."""
            return values

    class Model:
        def predict(self, values):
            """Mark the first fixture window as anomalous."""
            return np.array([-1, 1])

        def decision_function(self, values):
            """Return fixed decision scores for the two fixture windows."""
            return np.array([-0.8, 0.1])

    source = pd.DataFrame([
        {"ip": "203.0.113.1", "window_start": pd.Timestamp("2026-09-18T00:00Z"),
         **{column: 1.0 for column in detector.FEATURE_COLUMNS}},
        {"ip": "203.0.113.1", "window_start": pd.Timestamp("2026-09-18T00:01Z"),
         **{column: 2.0 for column in detector.FEATURE_COLUMNS}},
    ])
    original_columns = set(source.columns)

    scored, anomaly_count = detector._score_windows(
        source, {"scaler": Scaler(), "model": Model(), "training_decision_floor": -1.0}
    )

    assert anomaly_count == 1
    assert scored["is_anomaly"].tolist() == [True, False]
    assert scored["window_score"].tolist() == [94, 0]
    assert set(source.columns) == original_columns


def test_build_ip_score_preserves_existing_reason_and_evidence_contract(monkeypatch):
    """Keep minimum-window reason and supporting evidence semantics stable."""
    monkeypatch.setenv("LOG_WS_AI_MIN_IP_WINDOWS", "3")
    source = pd.DataFrame([
        {"ip": "203.0.113.1", "window_start": pd.Timestamp("2026-09-18T00:00Z"),
         "is_anomaly": True, "decision": -0.8, "window_score": 94,
         **{column: 1.0 for column in detector.FEATURE_COLUMNS}},
        {"ip": "203.0.113.1", "window_start": pd.Timestamp("2026-09-18T00:01Z"),
         "is_anomaly": False, "decision": 0.1, "window_score": 0,
         **{column: 2.0 for column in detector.FEATURE_COLUMNS}},
    ])

    score = detector._build_ip_score(
        "203.0.113.1", source,
        {"ai_anomaly_score": 70, "ai_evidence_json": "[]"},
        {"model_version": "fixture", "training_decision_floor": -1.0},
        "2026-09-18T00:02:00+00:00", False,
    )

    assert score["score"] == 94
    assert score["score_delta"] == 24
    assert score["reason"] == "insufficient_ip_windows"
    assert len(score["evidence"]) == 1
    assert score["evidence"][0]["window_score"] == 94
