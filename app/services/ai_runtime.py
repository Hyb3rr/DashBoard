"""Independent Stage-2 AI scoring workload.

This worker is deliberately outside the collector hot path.  It owns only
periodic model training/scoring and uses a PostgreSQL advisory lock so a
second app process cannot run the same cycle concurrently.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import inspect
import logging
import os
from typing import Any, Callable

from ..ai.detector import MODEL_KEY, score_cycle, train_model
from ..db import postgres

logger = logging.getLogger(__name__)
LOCK_KEY = "ip-intelligence:ai-stage-2"


def _interval_seconds() -> float:
    try:
        return max(1.0, float(os.getenv("AI_RUNTIME_INTERVAL_SECONDS", "300")))
    except (TypeError, ValueError):
        return 300.0


def _enabled() -> bool:
    return os.getenv("AI_RUNTIME_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}


class AiRuntime:
    def __init__(
        self,
        run_cycle: Callable[[], dict[str, Any]] | None = None,
        initial_delay_seconds: float | None = None,
    ) -> None:
        self._run_cycle = run_cycle or self._run_cycle_sync
        self._initial_delay_seconds = initial_delay_seconds
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None
        self._last_run: dict[str, Any] | None = None

    async def start(self) -> None:
        if not _enabled() or self._task:
            return
        self._stop.clear()
        self._task = asyncio.create_task(self.run(), name="ai-stage-2-runtime")

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None

    async def run(self) -> None:
        first_delay = self._initial_delay_seconds
        if first_delay is None:
            first_delay = _interval_seconds()
        while not self._stop.is_set():
            await self._wait_until_scheduled(first_delay)
            if self._stop.is_set():
                return
            started = asyncio.get_running_loop().time()
            try:
                if inspect.iscoroutinefunction(self._run_cycle):
                    self._last_run = await self._run_cycle()
                else:
                    self._last_run = await asyncio.to_thread(self._run_cycle)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # isolated workload: never kill FastAPI
                self._last_run = {"status": "failed", "error": f"{type(exc).__name__}: {exc}"[:240]}
                logger.exception("AI Stage-2 cycle failed")
            elapsed = asyncio.get_running_loop().time() - started
            first_delay = max(0.0, _interval_seconds() - elapsed)

    async def _wait_until_scheduled(self, delay: float) -> None:
        if delay <= 0:
            return
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=delay)
        except asyncio.TimeoutError:
            return

    def status(self) -> dict[str, Any]:
        return {
            "enabled": _enabled(),
            "running": bool(self._task and not self._task.done()),
            "interval_seconds": _interval_seconds(),
            "last_run": self._last_run,
        }

    @staticmethod
    def _run_cycle_sync() -> dict[str, Any]:
        # Detector functions own their transaction boundaries and explicitly
        # commit model state and scores. Use one dedicated connection context,
        # not the repository transaction wrapper, to avoid nested commits.
        with postgres.connect() as conn:
            acquired = conn.execute(
                "SELECT pg_try_advisory_lock(hashtextextended(%s, 0)) AS acquired",
                (LOCK_KEY,),
            ).fetchone()["acquired"]
            if not acquired:
                return {"status": "locked"}
            try:
                model = train_model(conn)
                scored = score_cycle(conn)
                return {
                    "status": "completed",
                    "at": datetime.now(timezone.utc).isoformat(),
                    "model": model,
                    "scored": scored,
                    "model_key": MODEL_KEY,
                }
            except Exception:
                # A failed SQL statement aborts the transaction. Roll it back
                # before releasing the session-level advisory lock, otherwise
                # the cleanup query masks the real failure.
                conn.rollback()
                raise
            finally:
                conn.execute(
                    "SELECT pg_advisory_unlock(hashtextextended(%s, 0))",
                    (LOCK_KEY,),
                )


ai_runtime = AiRuntime()
