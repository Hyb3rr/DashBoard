import asyncio
import threading

from app.core.fast_detection import EarlyDetection
from app.core import metrics
from app.collectors.websocket_collector import CollectorConfig, WebSocketCollector
from app.services.early_alerts import EarlyAlertPublisher
from app.services import early_alerts as early_alerts_module


def test_enqueue_is_bounded_and_non_blocking():
    publisher = EarlyAlertPublisher(maxsize=1)
    detection = EarlyDetection("sensitive_path_probe", "/.env", "GET", "/.env")

    assert publisher.enqueue(detection, "203.0.113.10") is True
    assert publisher.enqueue(detection, "203.0.113.10") is False
    assert metrics.snapshot()["counters"]["early_alert.queue_overflow"] == 1


def test_worker_publishes_sse_before_telegram_completion(monkeypatch):
    published = []
    telegram_started = asyncio.Event()
    release_telegram = asyncio.Event()

    async def fake_publish(event, payload):
        published.append((event, payload))

    async def slow_telegram(_message):
        telegram_started.set()
        await release_telegram.wait()
        return True

    monkeypatch.setattr(early_alerts_module, "send_message", slow_telegram)

    async def scenario():
        publisher = EarlyAlertPublisher(publish=fake_publish)
        await publisher.start()
        publisher.enqueue(EarlyDetection("sensitive_path_probe", "/.env", "GET", "/.env"), "203.0.113.10")
        await asyncio.wait_for(telegram_started.wait(), timeout=1)
        assert published[0][0] == "early_alert"
        release_telegram.set()
        await publisher.stop()

    asyncio.run(scenario())


def test_early_detection_happens_before_slow_storage(monkeypatch):
    commit_started = threading.Event()
    release_commit = threading.Event()
    detections = []
    collector = WebSocketCollector(
        CollectorConfig(True, "wss://example.test", "secret", "access", "source", 1, 1000, 300)
    )

    def slow_commit(*_args, **_kwargs):
        commit_started.set()
        release_commit.wait(timeout=2)
        return 42, 0, set(), []

    async def scenario():
        monkeypatch.setattr(collector, "_commit_batch", slow_commit)
        monkeypatch.setattr(collector, "_after_commit", lambda *_args: asyncio.sleep(0))
        monkeypatch.setattr(early_alerts_module.early_alerts, "enqueue", lambda detection, ip=None: detections.append((detection, ip)) or True)
        collector._stop.clear()
        collector._storage_task = asyncio.create_task(collector._storage_loop())
        await collector.handle_message(
            '{"type":"lines","items":["203.0.113.10 - - [24/Aug/2026:12:00:00 +0000] \\\"GET /.env HTTP/1.1\\\" 404 1 \\\"-\\\" \\\"client\\\""]}',
            0,
        )
        await asyncio.sleep(0.05)
        assert commit_started.is_set()
        assert detections and detections[0][1] == "203.0.113.10"
        release_commit.set()
        await collector._storage_queue.join()
        collector._stop.set()
        collector._storage_task.cancel()
        await asyncio.gather(collector._storage_task, return_exceptions=True)

    asyncio.run(scenario())
