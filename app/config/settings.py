"""Application paths and runtime configuration."""

from pathlib import Path


APP_DIR = Path(__file__).resolve().parents[1]
PROJECT_DIR = APP_DIR.parent
DATA_DIR = PROJECT_DIR / "data"
DB_PATH = DATA_DIR / "hub.db"
REGION_SEED_PATH = DATA_DIR / "region_profiles.seed.json"
SAMPLE_LOG = PROJECT_DIR / "apache_logs.log"
TOR_EXIT_LIST = DATA_DIR / "tor_exit_nodes.txt"
