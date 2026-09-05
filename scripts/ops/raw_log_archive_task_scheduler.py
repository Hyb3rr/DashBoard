"""Windows Task Scheduler adapter for the universal raw archive job."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

TASK_NAME = "Sentinel Raw Log Archive"
ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ENV_FILE = Path.home() / ".config" / "sentinel-backup.env"


def _env_file(path: str | Path) -> dict[str, str]:
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
    candidate = root / ".venv" / "Scripts" / "python.exe"
    if candidate.is_file():
        return str(candidate)
    candidate = root / ".venv" / "bin" / "python"
    return str(candidate if candidate.is_file() else Path(sys.executable))


def task_xml(root: Path = ROOT, env_file: str | Path = DEFAULT_ENV_FILE) -> bytes:
    task = ET.Element("Task", {"version": "1.4"})
    ET.SubElement(task, "RegistrationInfo")
    triggers = ET.SubElement(task, "Triggers")
    trigger = ET.SubElement(triggers, "CalendarTrigger", {"id": "Hourly"})
    ET.SubElement(trigger, "StartBoundary").text = "2000-01-01T00:00:00"
    ET.SubElement(trigger, "Enabled").text = "true"
    repetition = ET.SubElement(trigger, "Repetition")
    ET.SubElement(repetition, "Interval").text = "PT1H"
    ET.SubElement(repetition, "StopAtDurationEnd").text = "false"
    principals = ET.SubElement(task, "Principals")
    principal = ET.SubElement(principals, "Principal", {"id": "Author"})
    ET.SubElement(principal, "LogonType").text = "InteractiveToken"
    ET.SubElement(principal, "RunLevel").text = "LeastPrivilege"
    settings = ET.SubElement(task, "Settings")
    ET.SubElement(settings, "MultipleInstancesPolicy").text = "IgnoreNew"
    ET.SubElement(settings, "StartWhenAvailable").text = "true"
    ET.SubElement(settings, "ExecutionTimeLimit").text = "PT2H"
    actions = ET.SubElement(task, "Actions", {"Context": "Author"})
    action = ET.SubElement(actions, "Exec")
    ET.SubElement(action, "Command").text = python_executable(root)
    ET.SubElement(action, "Arguments").text = (
        f'"{Path(__file__).resolve()}" --run --env-file "{Path(env_file).expanduser()}"'
    )
    ET.SubElement(action, "WorkingDirectory").text = str(root)
    return ET.tostring(task, encoding="utf-8", xml_declaration=True)


def install(task_name: str = TASK_NAME, root: Path = ROOT,
            env_file: str | Path = DEFAULT_ENV_FILE) -> None:
    if os.name != "nt":
        raise RuntimeError("Windows Task Scheduler adapter requires Windows")
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as handle:
        xml_path = Path(handle.name)
        handle.write(task_xml(root, env_file))
    try:
        completed = subprocess.run(
            ["schtasks.exe", "/Create", "/TN", task_name, "/XML", str(xml_path), "/F"],
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(f"schtasks create failed with exit code {completed.returncode}")
    finally:
        xml_path.unlink(missing_ok=True)


def uninstall(task_name: str = TASK_NAME) -> None:
    if os.name != "nt":
        raise RuntimeError("Windows Task Scheduler adapter requires Windows")
    completed = subprocess.run(["schtasks.exe", "/Delete", "/TN", task_name, "/F"], check=False)
    if completed.returncode not in (0, 1):
        raise RuntimeError(f"schtasks delete failed with exit code {completed.returncode}")


def run(env_file: str | Path = DEFAULT_ENV_FILE, root: Path = ROOT) -> int:
    environment = os.environ.copy()
    environment.update(_env_file(env_file))
    environment["PYTHONPATH"] = str(root)
    completed = subprocess.run(
        [python_executable(root), "-m", "scripts.ops.raw_log_archive_job"],
        cwd=root,
        env=environment,
        check=False,
    )
    return completed.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="Install or run raw archive Task Scheduler adapter")
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--install", action="store_true")
    actions.add_argument("--uninstall", action="store_true")
    actions.add_argument("--run", action="store_true")
    parser.add_argument("--env-file", default=str(DEFAULT_ENV_FILE))
    parser.add_argument("--task-name", default=TASK_NAME)
    args = parser.parse_args()
    if args.install:
        install(args.task_name, ROOT, args.env_file)
        return 0
    if args.uninstall:
        uninstall(args.task_name)
        return 0
    return run(args.env_file, ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
