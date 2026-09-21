"""Application paths and runtime configuration."""

from pathlib import Path
import os
import ipaddress

from dotenv import load_dotenv

load_dotenv()


APP_DIR = Path(__file__).resolve().parents[1]
PROJECT_DIR = APP_DIR.parent
WEB_DIR = APP_DIR / "web"
TEMPLATES_DIR = WEB_DIR / "templates"
STATIC_DIR = WEB_DIR / "static"
DATA_DIR = PROJECT_DIR / "data"
DATA_BACKEND = "split"
APP_ROLE = os.getenv("APP_ROLE", "all").strip().lower() or "all"
if APP_ROLE not in {"all", "api", "collector", "worker", "ai"}:
    raise ValueError(
        "APP_ROLE must be one of: all, api, collector, worker, ai; "
        "run the standalone scheduler with python -m scripts.ops.data_scheduler"
    )
DATASET_LIVE_ID = os.getenv("DATASET_LIVE_ID", "live").strip() or "live"
TRUST_PROXY_HEADERS = os.getenv("TRUST_PROXY_HEADERS", "false").strip().lower() in {"1", "true", "yes", "on"}
_TRUSTED_PROXY_CIDR_VALUES = tuple(value.strip() for value in os.getenv("TRUSTED_PROXY_CIDRS", "").split(",") if value.strip())
try:
    TRUSTED_PROXY_NETWORKS = tuple(ipaddress.ip_network(value, strict=False) for value in _TRUSTED_PROXY_CIDR_VALUES)
except ValueError as exc:
    raise ValueError("TRUSTED_PROXY_CIDRS contains an invalid network") from exc
AUTH_REQUIRED = os.getenv("AUTH_REQUIRED", "false").strip().lower() in {"1", "true", "yes", "on"}
AUTH_IDENTITY_HEADER = os.getenv("AUTH_IDENTITY_HEADER", "X-Forwarded-User").strip() or "X-Forwarded-User"
AUTH_ROLE_HEADER = os.getenv("AUTH_ROLE_HEADER", "X-Forwarded-Groups").strip() or "X-Forwarded-Groups"
_AUTH_PROXY_CIDR_VALUES = tuple(value.strip() for value in os.getenv("AUTH_TRUSTED_PROXY_CIDRS", "").split(",") if value.strip())
try:
    AUTH_TRUSTED_PROXY_NETWORKS = tuple(ipaddress.ip_network(value, strict=False) for value in _AUTH_PROXY_CIDR_VALUES)
except ValueError as exc:
    raise ValueError("AUTH_TRUSTED_PROXY_CIDRS contains an invalid network") from exc
TRUSTED_HOSTS = tuple(value.strip() for value in os.getenv("TRUSTED_HOSTS", "localhost,127.0.0.1,testserver,test").split(",") if value.strip())
if not TRUSTED_HOSTS:
    raise ValueError("TRUSTED_HOSTS must contain at least one host")
SECURITY_HEADERS_ENABLED = os.getenv("SECURITY_HEADERS_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
REGION_SEED_PATH = DATA_DIR / "region_profiles.seed.json"
TOR_EXIT_LIST = DATA_DIR / "tor_exit_nodes.txt"
AI_MODEL_PATH = DATA_DIR / "models" / "isolation_forest_v1.joblib"
