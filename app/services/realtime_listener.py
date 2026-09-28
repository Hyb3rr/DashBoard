"""PostgreSQL notification bridge for process-local SSE fan-out."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
import os
import threading
from typing import Any, Awaitable, Callable

logger = logging.getLogger(__name__)


class PostgresRealtimeListener:
    """Turn durable change-log wake-ups into local bus events.

    Notifications are only hints. Clients still fetch the durable cursor and
    change rows, so a dropped notification cannot lose an update.
    """

    def __init__(self, publish: Callable[[str, dict[str, Any]], Awaitable[None]]) -> None:
        """Initialize listener state and the local event publisher callback."""
        self._publish = publish
        self._task: asyncio.Task[None] | None = None
        self._stop = threading.Event()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._status = "stopped"
        self._failures = 0
        self._last_error: str | None = None

    async def start(self) -> None:
        """Start the PostgreSQL notification listener when database access is configured."""
        if self._task and not self._task.done():
            return
        if not os.getenv("POSTGRES_DSN"):
            self._status = "disabled"
            return
        self._stop.clear()
        self._loop = asyncio.get_running_loop()
        self._status = "starting"
        self._task = asyncio.create_task(asyncio.to_thread(self._listen), name="postgres-realtime-listener")

    async def stop(self) -> None:
        """Signal the listener thread to stop and wait for its task to finish."""
        self._stop.set()
        if self._task:
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None
        self._status = "stopped"

    def status(self) -> dict[str, Any]:
        """Return the listener state, failure count, and most recent error type."""
        task_state = "running" if self._task and not self._task.done() else self._status
        return {
            "status": task_state,
            "failures": self._failures,
            "last_error": self._last_error,
        }

    def _listen(self) -> None:
        """Reconnect to PostgreSQL and forward durable change-feed wake-up cursors."""
        import psycopg
        backoff = 1.0
        while not self._stop.is_set():
            try:
                with psycopg.connect(os.environ["POSTGRES_DSN"], autocommit=True) as conn:
                    conn.execute("LISTEN sentinel_ip_changes")
                    backoff = 1.0
                    self._status = "running"
                    self._last_error = None
                    while not self._stop.is_set():
                        for notify in conn.notifies(timeout=1.0, stop_after=1):
                            if self._stop.is_set():
                                break
                            try:
                                cursor = int(notify.payload)
                            except (TypeError, ValueError):
                                continue
                            if self._loop and not self._loop.is_closed():
                                asyncio.run_coroutine_threadsafe(
                                    self._publish("ip_changes", {
                                        "cursor": cursor,
                                        "published_at": datetime.now(timezone.utc).isoformat(),
                                        "source": "postgres_notify",
                                    }), self._loop)
            except Exception as exc:
                if self._stop.is_set():
                    break
                self._failures += 1
                self._last_error = type(exc).__name__
                self._status = "retrying"
                logger.warning("PostgreSQL realtime listener unavailable; retrying: %s", type(exc).__name__)
                self._stop.wait(backoff)
                backoff = min(30.0, backoff * 2)
        if self._stop.is_set():
            self._status = "stopped"
