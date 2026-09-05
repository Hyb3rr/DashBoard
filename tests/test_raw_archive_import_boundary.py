import asyncio
import importlib

import pytest


def test_collector_import_does_not_require_azure_sdk():
    collector_module = importlib.import_module("app.collectors.websocket_collector")
    archive_module = importlib.import_module("app.services.raw_log_archive")

    assert collector_module.WebSocketCollector
    assert archive_module.RawLogArchive


@pytest.mark.asyncio
async def test_local_archive_starts_without_azure_configuration(tmp_path, monkeypatch):
    monkeypatch.delenv("BACKUP_AZURE_ACCOUNT", raising=False)
    monkeypatch.delenv("BACKUP_AZURE_CONTAINER", raising=False)

    from app.services.raw_log_archive import RawLogArchive

    archive = RawLogArchive("test-source", tmp_path)
    await archive.start()
    try:
        assert archive.status()["upload_status"] == "UNAVAILABLE"
        assert archive._task is not None
    finally:
        await archive.stop()
