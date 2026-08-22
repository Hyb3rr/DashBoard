"""Parity execution tests (marked integration)."""

import pytest


@pytest.mark.parity
@pytest.mark.integration
def test_parity_full_fixture_runs_both_pipelines():
    pytest.skip("Legacy parity test retired with SQLite removal")
