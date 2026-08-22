"""Replay consistency tests — require PostgreSQL/ClickHouse, marked @integration."""
import pytest


@pytest.mark.integration
def test_file_and_websocket_replay_produce_same_observation():
    pytest.skip("Requires PostgreSQL integration environment")
