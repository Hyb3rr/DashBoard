import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))
os.environ["INTEL_AUTO_UPDATE_ON_STARTUP"] = "false"
os.environ["RARE_PATH_ENABLED"] = "false"


def pytest_sessionfinish(session, exitstatus):
    """Close PostgreSQL pool before pytest interpreter teardown."""
    from app.db import postgres

    postgres.close_pool()
