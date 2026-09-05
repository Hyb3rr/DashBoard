import plistlib
import subprocess

from scripts.ops import raw_log_archive_launchd as launchd


def test_plist_calls_universal_job_with_venv_and_hourly_interval(tmp_path):
    data = launchd.plist_data(tmp_path, tmp_path / "backup.env")
    assert data["ProgramArguments"][-2:] == ["--env-file", str(tmp_path / "backup.env")]
    assert data["ProgramArguments"][1].endswith("raw_log_archive_launchd.py")
    assert data["StartInterval"] == 3600
    assert data["RunAtLoad"] is False
    assert "AZURE_CLIENT_SECRET" not in str(data)


def test_env_file_is_parsed_without_shell_execution(tmp_path):
    env_file = tmp_path / "backup.env"
    env_file.write_text("export BACKUP_AZURE_ACCOUNT=example\n# comment\nQUOTED='safe value'\n", encoding="utf-8")
    assert launchd._env_file(env_file) == {
        "BACKUP_AZURE_ACCOUNT": "example",
        "QUOTED": "safe value",
    }


def test_run_invokes_universal_module_and_propagates_exit_code(tmp_path, monkeypatch):
    calls = {}

    def fake_run(command, **kwargs):
        calls.update(command=command, kwargs=kwargs)
        return subprocess.CompletedProcess(command, 7)

    monkeypatch.setattr(launchd.subprocess, "run", fake_run)
    assert launchd.run(tmp_path / "missing.env", tmp_path) == 7
    assert calls["command"][1:4] == ["-m", "scripts.ops.raw_log_archive_job"]
    assert calls["kwargs"]["cwd"] == tmp_path
    assert calls["kwargs"]["env"]["PYTHONPATH"] == str(tmp_path)
