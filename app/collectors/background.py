"""Background collector loops kept off the WebSocket receive path."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from ..core import metrics
from ..db import postgres as postgres_store
from ..services.profiles import ensure_profile_postgres, refresh_due_profiles
from ..services.realtime_bus import RealtimeBus

logger = logging.getLogger(__name__)


async def governor_loop(collector: Any, early_alerts: Any) -> None:
    """Adjust workload based on storage and early-alert queue pressure."""
    while not collector.stop_event.is_set():
        oldest_age_ms = 0.0
        if collector.storage_worker.oldest_started is not None:
            oldest_age_ms = (
                time.monotonic() - collector.storage_worker.oldest_started
            ) * 1000
        collector._governor.update(
            collector.storage_worker.queue.qsize(),
            oldest_age_ms,
            early_alerts.status()["queue_depth"],
        )
        try:
            await asyncio.wait_for(collector.stop_event.wait(), timeout=1.0)
        except asyncio.TimeoutError:
            pass


def enrich_one(ip: str) -> tuple[str, bool, str | None]:
    """Enrich one IP in a worker thread and return its result and error."""
    try:
        data, error = asyncio.run(ensure_profile_postgres(ip, change_reason="enrichment"))
        return ip, bool(data and not error), error
    except Exception as exc:
        return ip, False, f"{type(exc).__name__}: {exc}"


@dataclass
class EnrichmentWorker:
    """Own enrichment requests, deduplication and background processing."""

    stop_event: asyncio.Event
    governor: Any
    bus: RealtimeBus
    now: Callable[[], str]
    env_int: Callable[[str, int, int], int]
    enrich: Callable[[str], tuple[str, bool, str | None]] = enrich_one
    queue: asyncio.Queue[str] = field(
        default_factory=lambda: asyncio.Queue(maxsize=1000)
    )
    pending: set[str] = field(default_factory=set)
    deferred: set[str] = field(default_factory=set)

    def schedule(self, ip: str) -> bool:
        """Queue an IP once, deferring it when pressure or capacity is high."""
        if not self.governor.allow_enrichment():
            self.deferred.add(ip)
            return False
        if ip in self.pending:
            return False
        try:
            self.queue.put_nowait(ip)
        except asyncio.QueueFull:
            self.deferred.add(ip)
            return False
        self.pending.add(ip)
        return True

    async def run(self) -> None:
        """Batch queued IPs and publish a cursor after successful enrichment."""
        concurrency = self.env_int("ENRICHMENT_CONCURRENCY", 4, 1)
        batch_size = self.env_int("ENRICHMENT_BATCH_SIZE", 20, 1)
        while not self.stop_event.is_set():
            try:
                first = await asyncio.wait_for(self.queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                first = None
            batch = [first] if first else []
            while len(batch) < batch_size:
                try:
                    batch.append(self.queue.get_nowait())
                except asyncio.QueueEmpty:
                    break
            deferred = list(self.deferred)
            self.deferred.clear()
            capacity = max(0, batch_size - len(batch))
            batch.extend(deferred[:capacity])
            self.deferred.update(deferred[capacity:])
            batch = list(dict.fromkeys(batch))
            if not batch:
                continue
            for ip in batch:
                self.pending.discard(ip)
            results = []
            for start in range(0, len(batch), concurrency):
                results.extend(await asyncio.gather(*[
                    asyncio.to_thread(self.enrich, ip)
                    for ip in batch[start:start + concurrency]
                ]))
            for ip, ok, error in results:
                if not ok and error:
                    logger.error("IP enrichment failed for %s: %s", ip, error)
            successful = [ip for ip, ok, _error in results if ok]
            if successful:
                with postgres_store.transaction() as pg_conn:
                    cursor = int(pg_conn.execute(
                        "SELECT COALESCE(MAX(seq),0) AS seq FROM ip_change_log"
                    ).fetchone()["seq"] or 0)
                await self.bus.publish("ip_changes", {
                    "cursor": cursor,
                    "count": len(successful),
                    "ips": sorted(successful),
                    "published_at": self.now(),
                })


@dataclass
class PrivacyRefreshWorker:
    """Own periodic privacy refresh execution and failure health state."""

    stop_event: asyncio.Event
    bus: RealtimeBus
    now: Callable[[], str]
    env_int: Callable[[str, int, int], int]
    consecutive_failures: int = 0
    last_error: str | None = None

    async def run(self) -> None:
        """Refresh due profiles and publish changes without blocking ingest."""
        interval = self.env_int("LOG_WS_PRIVACY_REFRESH_INTERVAL_SECONDS", 3600, 60)
        while not self.stop_event.is_set():
            try:
                await asyncio.wait_for(self.stop_event.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass
            if self.stop_event.is_set():
                break
            try:
                result = await refresh_due_profiles(
                    None, limit=self.env_int("PRIVACY_REFRESH_BATCH", 100, 1)
                )
                changed_ips = result.get("processed_ips", [])
                if changed_ips:
                    with postgres_store.transaction() as conn:
                        cursor = int(conn.execute(
                            "SELECT COALESCE(MAX(seq),0) AS seq FROM ip_change_log"
                        ).fetchone()["seq"] or 0)
                    await self.bus.publish("ip_changes", {
                        "cursor": cursor,
                        "count": len(changed_ips),
                        "ips": changed_ips,
                        "published_at": self.now(),
                    })
                self.consecutive_failures = 0
                self.last_error = None
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.consecutive_failures += 1
                self.last_error = f"{type(exc).__name__}: {exc}"
                metrics.increment("collector.privacy_refresh_failures")
                logger.warning(
                    "Privacy refresh failed (%s consecutive): %s",
                    self.consecutive_failures,
                    exc,
                )


async def publish_rare_changes(
    changed_ips: list[str], bus: RealtimeBus, now: Callable[[], str]
) -> None:
    """Read the committed cursor and publish a rare-path bus notification."""
    with postgres_store.transaction() as conn:
        cursor = int(conn.execute(
            "SELECT COALESCE(MAX(seq),0) AS seq FROM ip_change_log"
        ).fetchone()["seq"] or 0)
    await bus.publish("ip_changes", {
        "cursor": cursor,
        "count": len(changed_ips),
        "ips": changed_ips,
        "published_at": now(),
    })
