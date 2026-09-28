"""AI v2 detector tests — all require PostgreSQL/live data, marked @integration."""
import pytest
import pandas as pd

from app.ai.features import build_window_features_from_events


@pytest.mark.integration
def test_window_features_are_bounded_and_filter_ips():
    """Verify database-backed feature windows honor the bounded query contract."""
    pytest.skip("Requires PostgreSQL integration environment")


@pytest.mark.integration
def test_train_persists_artifact_and_score_does_not_fit_again():
    """Verify trained artifacts are reused for scoring instead of refitting."""
    pytest.skip("Requires PostgreSQL integration environment")


@pytest.mark.integration
def test_inactive_ai_score_expires_without_deleting_row():
    """Verify inactive AI scores expire without deleting their persisted rows."""
    pytest.skip("Requires PostgreSQL integration environment")


def test_event_features_filter_inputs_and_aggregate_utc_minute():
    """Preserve time/IP filtering and behavioral features while grouping events."""
    events = [
        {
            "timestamp": "2026-09-25T12:01:05Z", "src_ip": "203.0.113.1",
            "path": "/.env", "method": "GET", "status": 404,
            "bytes_sent": 100, "user_agent": "agent-a",
        },
        {
            "timestamp": "2026-09-25T12:01:15Z", "src_ip": "203.0.113.1",
            "path": "/wp-login.php", "method": "POST", "status": 500,
            "bytes_sent": 300, "user_agent": "agent-b",
        },
        {
            "timestamp": "2026-09-25T12:01:20Z", "src_ip": "203.0.113.2",
            "path": "/", "method": "GET", "status": 200,
            "bytes_sent": 50, "user_agent": "agent-c",
        },
        {
            "timestamp": "2026-09-25T12:02:00Z", "src_ip": "203.0.113.1",
            "path": "/outside-window", "method": "GET", "status": 200,
            "bytes_sent": 500, "user_agent": "agent-a",
        },
    ]

    frame = build_window_features_from_events(
        events,
        start_at="2026-09-25T12:01:00Z",
        end_at="2026-09-25T12:02:00Z",
        ips=["203.0.113.1"],
    )

    assert len(frame) == 1
    row = frame.iloc[0]
    assert row["ip"] == "203.0.113.1"
    assert row["window_start"] == pd.Timestamp("2026-09-25T12:01:00Z")
    assert row["requests"] == 2
    assert row["unique_paths"] == 2
    assert row["ratio_404"] == 0.5
    assert row["ratio_5xx"] == 0.5
    assert row["post_ratio"] == 0.5
    assert row["sensitive_hits"] == 1
    assert row["login_attempts"] == 1
    assert row["avg_request_interval"] == 10
    assert row["unique_user_agents"] == 2
    assert row["bytes_avg"] == 200
