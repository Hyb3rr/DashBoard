import pandas as pd
from datetime import datetime, timezone

from app.ai import detector


def _frame(rows=12, ips=("203.0.113.1", "203.0.113.2", "203.0.113.3")):
    return pd.DataFrame(
        [
            {"ip": ip, "window_start": pd.Timestamp("2026-09-18T00:00Z") + pd.Timedelta(minutes=index), "requests": index}
            for index, ip in enumerate((ips * rows)[:rows])
        ]
    )


def test_training_bound_is_deterministic_and_preserves_multiple_ips(monkeypatch):
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
    monkeypatch.setenv("AI_TRAIN_MAX_IPS", "10")
    monkeypatch.setenv("AI_TRAIN_MAX_WINDOWS", "100")
    frame = _frame(6, ("203.0.113.1", "203.0.113.2"))
    bounded, metadata = detector._bound_training_frame(frame)
    assert len(bounded) == len(frame)
    assert bounded["ip"].nunique() == 2
    assert metadata["training_input_bounded"] is False


def test_fit_model_uses_controlled_worker_count(monkeypatch):
    monkeypatch.setenv("AI_TRAIN_N_JOBS", "1")
    frame = _frame(60, ("203.0.113.1", "203.0.113.2", "203.0.113.3"))
    for column in detector.FEATURE_COLUMNS:
        frame[column] = 1.0
    bundle = detector._fit_model_frame(frame, {"model_version": "test", "trained_at": "now", "training_start": "start", "training_end": "end"})
    assert bundle["training_windows"] == 60
    assert bundle["training_input_bounded"] is False


def test_training_source_query_is_bounded_before_fetchall(monkeypatch):
    class Result:
        def fetchall(self):
            return []

    class Connection:
        def __init__(self):
            self.sql = ""
            self.params = None

        def execute(self, sql, params):
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
