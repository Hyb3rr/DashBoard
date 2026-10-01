import os
import shutil
import signal
import subprocess
import time
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _write_executable(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def _fake_project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    (root / "scripts").mkdir(parents=True)
    shutil.copy2(REPO_ROOT / "scripts/dev_run.sh", root / "scripts/dev_run.sh")
    (root / "infra/clickhouse").mkdir(parents=True)
    (root / "app").mkdir()
    (root / "data").mkdir()
    _write_executable(root / ".venv/bin/python", "#!/bin/sh\nexit 0\n")
    _write_executable(
        root / ".venv/bin/uvicorn",
        "#!/bin/sh\ntrap 'exit 0' TERM INT\nwhile :; do sleep 0.1; done\n",
    )
    (root / "scripts/ops").mkdir(parents=True)
    (root / "scripts/ops/init_storage.py").write_text("pass\n", encoding="utf-8")
    (root / "infra/clickhouse/config.xml").write_text("<clickhouse/>\n", encoding="utf-8")
    (root / "data/postgres").mkdir()
    (root / "data/postgres/PG_VERSION").write_text("16\n", encoding="utf-8")
    (root / "data/clickhouse").mkdir()

    bin_dir = root / "fake-bin"
    _write_executable(bin_dir / "pg_isready", "#!/bin/sh\nexit 0\n")
    _write_executable(bin_dir / "createdb", "#!/bin/sh\nexit 0\n")
    _write_executable(bin_dir / "curl", "#!/bin/sh\nexit 0\n")
    _write_executable(bin_dir / "nc", "#!/bin/sh\nexit 0\n")
    _write_executable(bin_dir / "clickhouse", "#!/bin/sh\nexit 1\n")
    return root


def _wait_for(path: Path, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.02)
    raise AssertionError(f"Timed out waiting for {path}")


def test_dev_launcher_refuses_second_owner_and_releases_lock(tmp_path):
    root = _fake_project(tmp_path)
    env = os.environ.copy()
    env.update(
        PATH=f"{root / 'fake-bin'}:{env['PATH']}",
        AI_EXPLAIN_WORKER_ENABLED="false",
        DEV_RUN_LOCK_DIR=str(root / "data/.dev-run.lock"),
        CLICKHOUSE_HTTP_PORT="18123",
        CLICKHOUSE_TCP_PORT="19001",
    )
    launcher = subprocess.Popen(
        ["bash", "scripts/dev_run.sh"],
        cwd=root,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    output_path = root / "launcher.log"
    try:
        _wait_for(root / "data/.dev-run.lock/pid")
        owner_pid = (root / "data/.dev-run.lock/pid").read_text(encoding="utf-8").strip()
        assert owner_pid == str(launcher.pid)

        second = subprocess.run(
            ["bash", "scripts/dev_run.sh"],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert second.returncode != 0
        assert f"Another dev_run launcher owns local app services (PID {launcher.pid})" in second.stderr
        assert launcher.poll() is None

        launcher.send_signal(signal.SIGTERM)
        stdout, _ = launcher.communicate(timeout=5)
        output_path.write_text(stdout, encoding="utf-8")
        assert launcher.returncode == 143
        assert "Launcher cleanup: reason=signal_TERM status=143" in stdout
        assert f"launcher_pid={launcher.pid}" in stdout
        assert not (root / "data/.dev-run.lock").exists()
    finally:
        if launcher.poll() is None:
            launcher.kill()
            launcher.wait(timeout=5)
