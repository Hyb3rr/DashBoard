import asyncio

import pytest

from app.collectors.websocket_collector import CollectorConfig, WebSocketCollector
from app.core.fast_detection import EarlyDetection
from app.services import early_alerts as early_alerts_module
from app.services.ai_runtime import AiRuntime


@pytest.mark.asyncio
async def test_slow_ai_does_not_block_ingest_alert_or_storage(monkeypatch):
    ai_started = asyncio.Event()
    release_ai = asyncio.Event()
    detected = []
    committed = []

    async def slow_ai():
        ai_started.set()
        await release_ai.wait()
        return {"status": "completed"}

    runtime = AiRuntime(slow_ai, initial_delay_seconds=0)
    await runtime.start()
    await asyncio.wait_for(ai_started.wait(), timeout=1)

    collector = WebSocketCollector(
        CollectorConfig(True, "wss://example.test", "secret", "access", "source", 1, 1000, 300)
    )

    def commit(lines, end_offset, current_offset, received_at=None):
        committed.append((lines, end_offset, current_offset))
        return end_offset, 11, {"203.0.113.10"}, []

    async def after_commit(*_args):
        return None

    monkeypatch.setattr(collector, "_commit_batch", commit)
    monkeypatch.setattr(collector, "_after_commit", after_commit)
    monkeypatch.setattr(
        early_alerts_module.early_alerts,
        "enqueue",
        lambda detection, ip=None: detected.append((detection, ip)) or True,
    )

    monkeypatch.setattr(
        collector._window_detector,
        "observe",
        lambda _line: [EarlyDetection("sensitive_path_probe", "/.env", "GET", "/.env", "203.0.113.10")],
    )
    collector._stop.clear()
    collector._storage_task = asyncio.create_task(collector._storage_loop())
    try:
        await collector.handle_message(
            '{"type":"lines","items":["203.0.113.10 raw access line"]}',
            0,
        )
        await collector._storage_queue.join()

        assert detected and detected[0][1] == "203.0.113.10"
        assert committed and committed[0][0] == ["203.0.113.10 raw access line"]
        assert collector.last_offset > 0
        assert runtime.status()["running"] is True
    finally:
        release_ai.set()
        await runtime.stop()
        collector._stop.set()
        collector._storage_task.cancel()
        await asyncio.gather(collector._storage_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_early_alert_sse_is_not_held_by_slow_telegram(monkeypatch):
    published = asyncio.Event()
    release_telegram = asyncio.Event()

    async def publish(event, _payload):
        if event == "early_alert":
            published.set()

    async def slow_telegram(_message):
        await release_telegram.wait()
        return True

    monkeypatch.setattr(early_alerts_module, "send_message", slow_telegram)
    publisher = early_alerts_module.EarlyAlertPublisher(publish=publish)
    await publisher.start()
    publisher.enqueue(EarlyDetection("sensitive_path_probe", "/.env", "GET", "/.env"), "203.0.113.10")
    await asyncio.wait_for(published.wait(), timeout=1)
    release_telegram.set()
    await publisher.stop()
