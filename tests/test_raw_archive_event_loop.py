import asyncio
import hashlib
import json
import subprocess
import time

import pytest


@pytest.mark.asyncio
async def test_local_compression_is_byte_for_byte_lossless(tmp_path, monkeypatch):
    monkeypatch.delenv("BACKUP_AZURE_ACCOUNT", raising=False)
    monkeypatch.delenv("BACKUP_AZURE_CONTAINER", raising=False)

    from app.services.raw_log_archive import RawLogArchive

    archive = RawLogArchive("compression", tmp_path)
    await archive.start()
    archive.tap(["raw unicode café", "second line"])
    await archive._queue.join()
    await archive.stop()

    compressed = list(tmp_path.rglob("*.log.zst"))
    assert len(compressed) == 1
    decoded = subprocess.run(
        ["zstd", "-q", "-d", "-c", str(compressed[0])],
        check=True,
        capture_output=True,
    ).stdout
    marker = json.loads(compressed[0].with_name(compressed[0].name + ".json").read_text())
    assert decoded == "raw unicode café\nsecond line\n".encode()
    assert hashlib.sha256(decoded).hexdigest() == marker["original_sha256"]


@pytest.mark.asyncio
async def test_slow_writer_does_not_block_event_loop(tmp_path, monkeypatch):
    from app.services.raw_log_archive import RawLogArchive

    archive = RawLogArchive("slow-writer", tmp_path)
    original = archive._write_line
    started = asyncio.Event()

    def slow_write(line, received_at):
        started.set()
        time.sleep(0.2)
        original(line, received_at)

    monkeypatch.setattr(archive, "_write_line", slow_write)
    await archive.start()
    try:
        archive.tap(["one"])
        await asyncio.wait_for(started.wait(), timeout=1)
        heartbeat_started = time.monotonic()
        await asyncio.sleep(0.02)
        heartbeat_elapsed = time.monotonic() - heartbeat_started
        assert heartbeat_elapsed < 0.1
        await archive._queue.join()
    finally:
        await archive.stop()
