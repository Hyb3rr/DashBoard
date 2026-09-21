import os
import sys
from pathlib import Path

import pytest
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).parents[1]))
os.environ["INTEL_AUTO_UPDATE_ON_STARTUP"] = "false"
os.environ["RARE_PATH_ENABLED"] = "false"


def pytest_addoption(parser):
    parser.addoption(
        "--integration",
        action="store_true",
        default=False,
        help="run native PostgreSQL/ClickHouse integration tests",
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "integration: requires native PostgreSQL/ClickHouse services")
    if config.getoption("--integration"):
        load_dotenv(dotenv_path=Path(__file__).parents[1] / ".env", override=False)
    else:
        os.environ["POSTGRES_DSN"] = ""
        os.environ["CLICKHOUSE_HOST"] = ""


def pytest_collection_modifyitems(config, items):
    if config.getoption("--integration"):
        return
    skip_integration = pytest.mark.skip(reason="integration tests require pytest --integration")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)


@pytest.fixture(autouse=True)
def isolated_raw_log_spool(tmp_path, monkeypatch):
    """Keep collector unit tests out of the production raw-log spool."""
    monkeypatch.setenv("RAW_LOG_ARCHIVE_SPOOL_DIR", str(tmp_path / "raw-log-spool"))


def pytest_sessionfinish(session, exitstatus):
    """Close PostgreSQL pool before pytest interpreter teardown."""
    from app.db import postgres

    postgres.close_pool()
