"""Application paths and runtime configuration."""

from pathlib import Path
import os

from dotenv import load_dotenv

load_dotenv()


APP_DIR = Path(__file__).resolve().parents[1]
PROJECT_DIR = APP_DIR.parent
DATA_DIR = PROJECT_DIR / "data"
DATA_BACKEND = "split"
DATASET_LIVE_ID = os.getenv("DATASET_LIVE_ID", "live").strip() or "live"
REGION_SEED_PATH = DATA_DIR / "region_profiles.seed.json"
TOR_EXIT_LIST = DATA_DIR / "tor_exit_nodes.txt"
AI_MODEL_PATH = DATA_DIR / "models" / "isolation_forest_v1.joblib"


