"""macOS launchd adapter for the universal raw archive job."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import plistlib
import subprocess
import sys


LABEL = "com.sentinel.raw-log-archive"
ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ENV_FILE = Path.home() / ".config" / "sentinel-backup.env"
DEFAULT_PLIST = Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def _env_file(path: str | Path) -> dict[str, str]:
    """Read trusted KEY=VALUE lines without executing the env file."""
    values: dict[str, str] = {}
    source = Path(path).expanduser()
    if not source.is_file():
        return values
    for raw_line in source.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[7:].strip()
        if separator and key.isidentifier():
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
                value = value[1:-1]
            values[key] = value
    return values


def python_executable(root: Path = ROOT) -> str:
    candidate = root / ".venv" / "bin" / "python"
    return str(candidate if candidate.is_file() else Path(sys.executable))


def plist_data(root: Path = ROOT, env_file: str | Path = DEFAULT_ENV_FILE,
               plist_path: str | Path = DEFAULT_PLIST) -> dict:
    log_dir = root / "data" / "logs"
    return {
        "Label": LABEL,
        "ProgramArguments": [python_executable(root), str(Path(__file__).resolve()), "--run", "--env-file", str(Path(env_file).expanduser())],
        "WorkingDirectory": str(root),
        "EnvironmentVariables": {
            "PYTHONPATH": str(root),
            "RAW_LOG_ARCHIVE_SPOOL_DIR": os.getenv("RAW_LOG_ARCHIVE_SPOOL_DIR", str(root / "data" / "raw-log-spool")),
        },
        "StartInterval": 3600,
        "RunAtLoad": False,
        "ProcessType": "Background",
        "LowPriorityIO": True,
        "ThrottleInterval": 60,
        "StandardOutPath": str(log_dir / "raw-log-archive-launchd.log"),
        "StandardErrorPath": str(log_dir / "raw-log-archive-launchd.err.log"),
    }


def install(plist_path: str | Path = DEFAULT_PLIST, root: Path = ROOT,
            env_file: str | Path = DEFAULT_ENV_FILE) -> Path:
    if sys.platform != "darwin":
        raise RuntimeError("macOS launchd adapter requires macOS")
    target = Path(plist_path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    (root / "data" / "logs").mkdir(parents=True, exist_ok=True)
    target.write_bytes(plistlib.dumps(plist_data(root, env_file, target), fmt=plistlib.FMT_XML))
    return target


def uninstall(plist_path: str | Path = DEFAULT_PLIST) -> None:
    if sys.platform != "darwin":
        raise RuntimeError("macOS launchd adapter requires macOS")
    Path(plist_path).expanduser().unlink(missing_ok=True)


def run(env_file: str | Path = DEFAULT_ENV_FILE, root: Path = ROOT) -> int:
    environment = os.environ.copy()
    environment.update(_env_file(env_file))
    environment["PYTHONPATH"] = str(root)
    command = [python_executable(root), "-m", "scripts.ops.raw_log_archive_job"]
    completed = subprocess.run(command, cwd=root, env=environment, check=False)
    return completed.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="Install or run raw archive launchd adapter")
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
