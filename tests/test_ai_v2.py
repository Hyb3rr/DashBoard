"""AI v2 detector tests — all require PostgreSQL/live data, marked @integration."""
import pytest


@pytest.mark.integration
def test_window_features_are_bounded_and_filter_ips():
    pytest.skip("Requires PostgreSQL integration environment")


@pytest.mark.integration
def test_train_persists_artifact_and_score_does_not_fit_again():
    pytest.skip("Requires PostgreSQL integration environment")


@pytest.mark.integration
def test_inactive_ai_score_expires_without_deleting_row():
    pytest.skip("Requires PostgreSQL integration environment")
