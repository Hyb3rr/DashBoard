"""Install and run the independent macOS data-refresh LaunchAgent."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import plistlib
import subprocess
import sys

from dotenv import dotenv_values


LABEL = "com.sentinel.data-scheduler"
ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ENV_FILE = ROOT / ".env"
DEFAULT_PLIST = Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"
DEFAULT_INTERVAL_SECONDS = 3600
MIN_INTERVAL_SECONDS = 60


def _read_env(path: str | Path) -> dict[str, str]:
    """Read string settings from the project env file without executing it."""
    return {
        key: value
        for key, value in dotenv_values(Path(path).expanduser()).items()
        if value is not None
    }


def _enabled(value: str | None) -> bool:
    """Interpret the scheduler enable flag using the app's accepted values."""
    return (value or "false").strip().lower() in {"1", "true", "yes", "on"}


def _interval_seconds(environment: dict[str, str]) -> int:
    """Validate the LaunchAgent interval and enforce a safe minimum cadence."""
    try:
        interval = int(environment.get("DATA_SCHEDULER_INTERVAL_SECONDS", DEFAULT_INTERVAL_SECONDS))
    except (TypeError, ValueError) as exc:
        raise ValueError("DATA_SCHEDULER_INTERVAL_SECONDS must be an integer") from exc
    if interval < MIN_INTERVAL_SECONDS:
        raise ValueError(f"DATA_SCHEDULER_INTERVAL_SECONDS must be at least {MIN_INTERVAL_SECONDS}")
    return interval


def python_executable(root: Path = ROOT) -> str:
    """Choose the repository virtualenv Python when available."""
    candidate = root / ".venv" / "bin" / "python"
    return str(candidate if candidate.is_file() else Path(sys.executable))


def plist_data(
    root: Path = ROOT,
    env_file: str | Path = DEFAULT_ENV_FILE,
) -> dict:
    """Build a login-started, periodically triggered scheduler plist."""
    environment = _read_env(env_file)
    log_dir = root / "data" / "logs"
    return {
        "Label": LABEL,
        "ProgramArguments": [
            python_executable(root), str(Path(__file__).resolve()), "--run",
            "--env-file", str(Path(env_file).expanduser()),
        ],
        "WorkingDirectory": str(root),
        "EnvironmentVariables": {"PYTHONPATH": str(root)},
        "StartInterval": _interval_seconds(environment),
        "RunAtLoad": True,
        "KeepAlive": False,
        "ProcessType": "Background",
        "LowPriorityIO": True,
        "ThrottleInterval": 60,
        "StandardOutPath": str(log_dir / "data-scheduler-launchd.log"),
        "StandardErrorPath": str(log_dir / "data-scheduler-launchd.err.log"),
    }


def install(
    plist_path: str | Path = DEFAULT_PLIST,
    root: Path = ROOT,
    env_file: str | Path = DEFAULT_ENV_FILE,
) -> Path:
    """Write the LaunchAgent plist without loading it into the user session."""
    if sys.platform != "darwin":
        raise RuntimeError("macOS launchd adapter requires macOS")
    target = Path(plist_path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    (root / "data" / "logs").mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.tmp")
    temporary.write_bytes(plistlib.dumps(plist_data(root, env_file), fmt=plistlib.FMT_XML))
    os.replace(temporary, target)
    return target


def uninstall(plist_path: str | Path = DEFAULT_PLIST) -> None:
    """Remove the LaunchAgent plist file without changing launchd session state."""
    if sys.platform != "darwin":
        raise RuntimeError("macOS launchd adapter requires macOS")
    Path(plist_path).expanduser().unlink(missing_ok=True)


def run(env_file: str | Path = DEFAULT_ENV_FILE, root: Path = ROOT) -> int:
    """Run one scheduler pass with project settings and return its exit code."""
    environment = os.environ.copy()
    environment.update(_read_env(env_file))
    environment["PYTHONPATH"] = str(root)
    if not _enabled(environment.get("DATA_SCHEDULER_ENABLED")):
        print("Data refresh scheduler disabled by configuration")
        return 0
    completed = subprocess.run(
        [python_executable(root), "-m", "scripts.ops.data_scheduler"],
        cwd=root,
        env=environment,
        check=False,
    )
    return completed.returncode


def main() -> int:
    """Parse LaunchAgent adapter actions and dispatch the selected operation."""
    parser = argparse.ArgumentParser(description="Manage the data scheduler LaunchAgent")
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--install", action="store_true")
    actions.add_argument("--uninstall", action="store_true")
    actions.add_argument("--run", action="store_true")
    parser.add_argument("--env-file", default=str(DEFAULT_ENV_FILE))
    parser.add_argument("--plist", default=str(DEFAULT_PLIST))
    args = parser.parse_args()
    if args.install:
        print(install(args.plist, ROOT, args.env_file))
        return 0
    if args.uninstall:
        uninstall(args.plist)
        return 0
    return run(args.env_file, ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
