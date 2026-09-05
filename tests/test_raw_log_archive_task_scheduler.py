import subprocess

from scripts.ops import raw_log_archive_task_scheduler as task_scheduler


def test_env_file_accepts_export_prefix(tmp_path):
    env_file = tmp_path / "backup.env"
    env_file.write_text("export BACKUP_AZURE_CONTAINER=sentinel-backups\n", encoding="utf-8")
    assert task_scheduler._env_file(env_file) == {"BACKUP_AZURE_CONTAINER": "sentinel-backups"}


def test_task_xml_is_hourly_low_privilege_and_secret_free(tmp_path):
    xml = task_scheduler.task_xml(tmp_path, tmp_path / "backup.env").decode()
    assert "PT1H" in xml
    assert "IgnoreNew" in xml
    assert "LeastPrivilege" in xml
    assert "AZURE_CLIENT_SECRET" not in xml
    assert str(tmp_path / "backup.env") in xml


def test_run_invokes_universal_job_and_propagates_exit_code(tmp_path, monkeypatch):
    calls = {}

    def fake_run(command, **kwargs):
        calls.update(command=command, kwargs=kwargs)
        return subprocess.CompletedProcess(command, 9)

    monkeypatch.setattr(task_scheduler.subprocess, "run", fake_run)
    assert task_scheduler.run(tmp_path / "missing.env", tmp_path) == 9
    assert calls["command"][1:] == ["-m", "scripts.ops.raw_log_archive_job"]
    assert calls["kwargs"]["cwd"] == tmp_path
    assert calls["kwargs"]["env"]["PYTHONPATH"] == str(tmp_path)


def test_install_is_not_available_on_non_windows(tmp_path, monkeypatch):
    monkeypatch.setattr(task_scheduler, "os", type("FakeOS", (), {"name": "posix"}))
    try:
        task_scheduler.install(root=tmp_path)
    except RuntimeError as exc:
        assert str(exc) == "Windows Task Scheduler adapter requires Windows"
    else:
        raise AssertionError("expected platform guard")
