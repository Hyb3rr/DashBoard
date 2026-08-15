from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from concurrent.futures import ProcessPoolExecutor
import hashlib
import json
import os
import socket
from typing import Any
from urllib.parse import urlencode

from ..ai.detector import load_model_bundle, score_cycle, train_model
from ..core.db import connect
from ..core.buckets import trim_buckets, upsert_buckets
from ..core.correlation import asn_clusters
from ..core.logs import parse_apache_combined, rebuild_observations_for_ips
from ..core.change_feed import append_ip_changes
from ..services.profiles import ensure_profile, refresh_due_profiles


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class CollectorConfig:
    enabled: bool
    url: str
    token: str
    log_key: str
    source_id: str
    batch_size: int
    flush_ms: int
    ai_interval_seconds: int

    @classmethod
    def from_env(cls) -> "CollectorConfig":
        enabled = os.getenv("LOG_WS_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}
        return cls(
            enabled=enabled,
            url=os.getenv("LOG_WS_URL", "").strip(),
            token=os.getenv("LOG_WS_TOKEN", "").strip(),
            log_key=os.getenv("LOG_WS_LOG_KEY", "access").strip() or "access",
            source_id=os.getenv("LOG_WS_SOURCE_ID", "azure-access").strip() or "azure-access",
            batch_size=_env_int("LOG_WS_BATCH_SIZE", 200, 1),
            flush_ms=_env_int("LOG_WS_FLUSH_MS", 500, 50),
            ai_interval_seconds=_env_int(
                "LOG_WS_AI_SCORE_INTERVAL_SECONDS",
                _env_int("LOG_WS_AI_INTERVAL_SECONDS", 300, 60),
                60,
            ),
        )

    @property
    def valid(self) -> bool:
        return bool(self.url and self.token and self.log_key and self.source_id)


class RealtimeBus:
    """Small process-local fanout bus used by the SSE endpoint."""

    def __init__(self) -> None:
        self._queues: set[asyncio.Queue[tuple[str, dict[str, Any]]]] = set()
        self._lock = asyncio.Lock()

    async def publish(self, event: str, payload: dict[str, Any]) -> None:
        async with self._lock:
            queues = tuple(self._queues)
        for queue in queues:
            try:
                queue.put_nowait((event, payload))
            except asyncio.QueueFull:
                # The next cursor-based delta request repairs a slow client.
                pass

    async def subscribe(self):
        queue: asyncio.Queue[tuple[str, dict[str, Any]]] = asyncio.Queue(maxsize=100)
        async with self._lock:
            self._queues.add(queue)
        try:
            while True:
                yield await queue.get()
        finally:
            async with self._lock:
                self._queues.discard(queue)


bus = RealtimeBus()


def _env_int(name: str, default: int, minimum: int) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default


def trim_change_log(conn) -> None:
    conn.execute(
        "DELETE FROM ip_change_log WHERE seq <= "
        "(SELECT CASE WHEN MAX(seq) > 50000 THEN MAX(seq) - 50000 ELSE 0 END FROM ip_change_log)"
    )


class WebSocketCollector:
    def __init__(self, config: CollectorConfig | None = None) -> None:
        self.config = config or CollectorConfig.from_env()
        self.state = "disabled" if not self.config.enabled else "config_error" if not self.config.valid else "connecting"
        self.last_error: str | None = None
        self.last_offset = 0
        self.pending_lines = 0
        self.reconnect_attempt = 0
        self.ai_last_run: str | None = None
        self.ai_status: dict[str, Any] = {}
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None
        self._ai_task: asyncio.Task | None = None
        self._fit_executor: ProcessPoolExecutor | None = None
        self._ai_lock = asyncio.Lock()
        self._enrichment_task: asyncio.Task | None = None
        self._privacy_task: asyncio.Task | None = None
        self._correlation_task: asyncio.Task | None = None
        self._enrichment_queue: asyncio.Queue[str] = asyncio.Queue(maxsize=1000)
        self._enrichment_pending: set[str] = set()
        self._owner = f"{socket.gethostname()}:{os.getpid()}"

    async def start(self) -> None:
        if self._task or not self.config.enabled or not self.config.valid:
            await self._publish_status()
            return
        self._stop.clear()
        try:
            self._fit_executor = ProcessPoolExecutor(max_workers=1)
        except (NotImplementedError, PermissionError):
            # Some restricted test/container runtimes lack POSIX semaphores.
            # Production uses the dedicated process executor; this fallback
            # keeps the service bootable where the OS cannot create one.
            self._fit_executor = None
        self._task = asyncio.create_task(self.run(), name="websocket-collector")
        self._ai_task = asyncio.create_task(self.ai_loop(), name="websocket-ai-scheduler")
        self._enrichment_task = asyncio.create_task(self.enrichment_loop(), name="websocket-enrichment")
        self._privacy_task = asyncio.create_task(self.privacy_loop(), name="websocket-privacy-refresh")
        self._correlation_task = asyncio.create_task(self.correlation_loop(), name="websocket-asn-correlation")

    async def stop(self) -> None:
        self._stop.set()
        tasks = [task for task in (self._task, self._ai_task, self._enrichment_task, self._privacy_task, self._correlation_task) if task]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._task = self._ai_task = self._enrichment_task = self._privacy_task = self._correlation_task = None
        if self._fit_executor:
            await asyncio.to_thread(self._fit_executor.shutdown, wait=True, cancel_futures=True)
            self._fit_executor = None
        self.state = "stopped"
        await self._publish_status()

    def status(self) -> dict[str, Any]:
        training = self.ai_status.get("training") or {}
        scoring = self.ai_status.get("scoring") or {}
        return {
            "enabled": self.config.enabled,
            "source_id": self.config.source_id,
            "log_key": self.config.log_key,
            "status": self.state,
            "last_offset": self.last_offset,
            "pending_lines": self.pending_lines,
            "reconnect_attempt": self.reconnect_attempt,
            "last_error": self.last_error,
            "last_ai_run": self.ai_last_run,
            "ai_scoring": self.ai_status,
            "ai_model_version": scoring.get("model_version") or training.get("model_version"),
            "ai_trained_at": training.get("trained_at"),
            "ai_train_status": training.get("status"),
            "ai_training_windows": training.get("windows", 0),
            "ai_last_score_at": self.ai_last_run,
            "ai_score_status": scoring.get("status"),
            "ai_last_error": scoring.get("error") or training.get("error"),
        }

    async def _publish_status(self) -> None:
        await asyncio.to_thread(self._persist_status)
        await bus.publish("collector_status", self.status())

    def _persist_status(self) -> None:
        conn = connect()
        try:
            now = utc_now()
            conn.execute(
                """INSERT INTO log_sources (source_id, log_key, status, last_error, updated_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(source_id) DO UPDATE SET status=excluded.status,
                     last_error=excluded.last_error, updated_at=excluded.updated_at""",
                (self.config.source_id, self.config.log_key, self.state, self.last_error, now),
            )
            conn.commit()
        finally:
            conn.close()

    def _load_offset(self) -> int:
        conn = connect()
        try:
            row = conn.execute("SELECT last_offset FROM log_sources WHERE source_id = ?", (self.config.source_id,)).fetchone()
            self.last_offset = int(row["last_offset"] if row else 0)
            if not row:
                conn.execute(
                    "INSERT INTO log_sources (source_id, log_key, status, updated_at) VALUES (?, ?, ?, ?)",
                    (self.config.source_id, self.config.log_key, self.state, utc_now()),
                )
                conn.commit()
            return self.last_offset
        finally:
            conn.close()

    def _acquire_lease(self) -> bool:
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=30)
        conn = connect()
        try:
            conn.execute(
                """INSERT INTO log_sources (source_id, log_key, status, updated_at, lease_owner, lease_expires_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(source_id) DO UPDATE SET
                     log_key=excluded.log_key, status=excluded.status, updated_at=excluded.updated_at,
                     lease_owner=excluded.lease_owner, lease_expires_at=excluded.lease_expires_at
                   WHERE log_sources.lease_owner = excluded.lease_owner
                      OR log_sources.lease_expires_at IS NULL
                      OR log_sources.lease_expires_at < excluded.updated_at""",
                (self.config.source_id, self.config.log_key, self.state, now.isoformat(), self._owner, expires.isoformat()),
            )
            row = conn.execute("SELECT lease_owner FROM log_sources WHERE source_id = ?", (self.config.source_id,)).fetchone()
            conn.commit()
            return bool(row and row["lease_owner"] == self._owner)
        finally:
            conn.close()

    def _renew_lease(self) -> None:
        conn = connect()
        try:
            now = datetime.now(timezone.utc)
            conn.execute(
                "UPDATE log_sources SET lease_expires_at = ?, updated_at = ? WHERE source_id = ? AND lease_owner = ?",
                ((now + timedelta(seconds=30)).isoformat(), now.isoformat(), self.config.source_id, self._owner),
            )
            conn.commit()
        finally:
            conn.close()

    async def _lease_loop(self) -> None:
        while not self._stop.is_set():
            await asyncio.sleep(10)
            await asyncio.to_thread(self._renew_lease)

    def _acquire_ai_lease(self) -> bool:
        now = _utc_datetime()
        expires = now + timedelta(minutes=30)
        conn = connect()
        try:
            _ = conn.execute(
                "INSERT OR IGNORE INTO ai_model_state (model_key, updated_at) VALUES (?, ?)",
                ("isolation_forest_v1", now.isoformat()),
            )
            conn.execute(
                """UPDATE ai_model_state SET lease_owner=?, lease_expires_at=?, updated_at=?
                   WHERE model_key=? AND (lease_owner IS NULL OR lease_owner=? OR lease_expires_at < ?)""",
                (self._owner, expires.isoformat(), now.isoformat(), "isolation_forest_v1", self._owner, now.isoformat()),
            )
            row = conn.execute("SELECT lease_owner FROM ai_model_state WHERE model_key=?", ("isolation_forest_v1",)).fetchone()
            conn.commit()
            return bool(row and row["lease_owner"] == self._owner)
        finally:
            conn.close()

    def _release_ai_lease(self) -> None:
        conn = connect()
        try:
            conn.execute(
                "UPDATE ai_model_state SET lease_owner=NULL, lease_expires_at=NULL, updated_at=? WHERE model_key=? AND lease_owner=?",
                (utc_now(), "isolation_forest_v1", self._owner),
            )
            conn.commit()
        finally:
            conn.close()

    def _connection_url(self, offset: int) -> str:
        separator = "&" if "?" in self.config.url else "?"
        return self.config.url + separator + urlencode({"token": self.config.token, "log": self.config.log_key, "offset": offset})

    async def run(self) -> None:
        if not self.config.valid:
            self.state = "config_error"
            await self._publish_status()
            return
        try:
            import websockets
        except ImportError:
            self.state = "config_error"
            self.last_error = "websockets dependency is not installed"
            await self._publish_status()
            return

        offset = await asyncio.to_thread(self._load_offset)
        backoff = 1.0
        while not self._stop.is_set():
            if not await asyncio.to_thread(self._acquire_lease):
                self.state = "standby"
                await self._publish_status()
                await asyncio.sleep(10)
                continue
            lease_task = asyncio.create_task(self._lease_loop(), name="websocket-lease")
            try:
                self.state = "connecting"
                await self._publish_status()
                url = self._connection_url(offset)
                async with websockets.connect(url, ping_interval=20, ping_timeout=20, max_size=8 * 1024 * 1024) as websocket:
                    self.state = "backlog"
                    self.reconnect_attempt = 0
                    self.last_error = None
                    await self._publish_status()
                    async for raw in websocket:
                        if self._stop.is_set():
                            break
                        result = await self.handle_message(raw, offset)
                        if result is not None:
                            offset = result
                            self.last_offset = offset
                    backoff = 1.0
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.last_error = f"{type(exc).__name__}: {exc}"[:240]
                self.reconnect_attempt += 1
                self.state = "retrying"
                await self._publish_status()
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30.0)
            finally:
                lease_task.cancel()
                await asyncio.gather(lease_task, return_exceptions=True)

    async def handle_message(self, raw: str | bytes, current_offset: int) -> int | None:
        try:
            message = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            return None
        if not isinstance(message, dict):
            return None
        kind = message.get("type")
        if kind == "lines":
            items = message.get("items")
            flushed_offset: int | None = None
            if isinstance(items, list):
                self._pending = getattr(self, "_pending", [])
                self._pending.extend(str(item) for item in items if isinstance(item, str))
                self.pending_lines = len(self._pending)
                while len(self._pending) >= self.config.batch_size:
                    batch = self._pending[:self.config.batch_size]
                    self._pending = self._pending[self.config.batch_size:]
                    end_offset = current_offset + sum(len(line.encode("utf-8")) + 1 for line in batch)
                    result = await asyncio.to_thread(self._commit_batch, batch, end_offset, current_offset)
                    current_offset, cursor, affected, new_ips = result
                    await self._after_commit(cursor, affected, new_ips)
                    flushed_offset = current_offset
                self.pending_lines = len(self._pending)
            return flushed_offset
        if kind == "backlog_done":
            self.state = "live"
            await self._publish_status()
            return None
        if kind != "offset":
            return None
        try:
            end_offset = int(message["value"])
        except (KeyError, TypeError, ValueError):
            return None
        if end_offset < current_offset:
            return None
        pending = getattr(self, "_pending", [])
        new_offset, cursor, affected, new_ips = await asyncio.to_thread(
            self._commit_batch, pending, end_offset, current_offset
        )
        self._pending = []
        self.pending_lines = 0
        await self._after_commit(cursor, affected, new_ips)
        return new_offset

    async def _after_commit(self, cursor: int, affected: set[str], new_ips: list[str]) -> None:
        for ip in new_ips:
            if ip in self._enrichment_pending:
                continue
            try:
                self._enrichment_queue.put_nowait(ip)
                self._enrichment_pending.add(ip)
            except asyncio.QueueFull:
                break
        if affected:
            await bus.publish("ip_changes", {"cursor": int(cursor), "count": len(affected)})

    def _commit_batch(self, lines: list[str], end_offset: int, current_offset: int) -> tuple[int, int, set[str], list[str]]:
        conn = connect()
        affected: set[str] = set()
        new_ips: list[str] = []
        try:
            lengths = [len(line.encode("utf-8")) + 1 for line in lines]
            start_offset = max(current_offset, end_offset - sum(lengths))
            position = start_offset
            now = utc_now()
            parsed_inserted: list[dict] = []
            for line, length in zip(lines, lengths):
                event = parse_apache_combined(line)
                position += length
                if not event:
                    continue
                ip = event["src_ip"]
                source = f"ws:{self.config.source_id}"
                line_hash = hashlib.sha256(f"{source}\0{position - length}\0{line}".encode()).hexdigest()
                cur = conn.execute(
                    """INSERT OR IGNORE INTO events
                       (source,line_hash,raw_line,timestamp,src_ip,method,path,status,bytes_sent,referer,user_agent,source_offset,imported_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (source, line_hash, line, event["timestamp"], event["src_ip"], event["method"], event["path"],
                     event["status"], event["bytes_sent"], event["referer"], event["user_agent"], position - length, now),
                )
                if cur.rowcount:
                    parsed_inserted.append(event)
                    affected.add(ip)
            upsert_buckets(conn, parsed_inserted)
            rebuild_observations_for_ips(conn, tuple(affected))
            trim_buckets(conn)
            append_ip_changes(conn, sorted(affected), "traffic", now)
            for ip in sorted(affected):
                if not conn.execute("SELECT 1 FROM ip_profiles WHERE ip = ?", (ip,)).fetchone():
                    new_ips.append(ip)
            trim_change_log(conn)
            conn.execute(
                """INSERT INTO log_sources (source_id, log_key, last_offset, status, last_event_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(source_id) DO UPDATE SET last_offset=excluded.last_offset,
                     status=excluded.status, last_event_at=COALESCE(excluded.last_event_at, log_sources.last_event_at), updated_at=excluded.updated_at""",
                (self.config.source_id, self.config.log_key, end_offset, self.state, now if affected else None, now),
            )
            conn.commit()
            cursor = conn.execute("SELECT COALESCE(MAX(seq), 0) AS seq FROM ip_change_log").fetchone()["seq"]
            return end_offset, int(cursor), affected, new_ips
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    async def enrichment_loop(self) -> None:
        while not self._stop.is_set():
            ip = await self._enrichment_queue.get()
            self._enrichment_pending.discard(ip)
            conn = connect()
            try:
                data, error = await ensure_profile(conn, ip)
                if data:
                    now = utc_now()
                    append_ip_changes(conn, (ip,), "enrichment", now)
                    trim_change_log(conn)
                    conn.commit()
                    cursor = conn.execute("SELECT COALESCE(MAX(seq), 0) AS seq FROM ip_change_log").fetchone()["seq"]
                    await bus.publish("ip_changes", {"cursor": int(cursor), "count": 1})
                elif error:
                    conn.rollback()
            except Exception:
                conn.rollback()
            finally:
                conn.close()

    async def privacy_loop(self) -> None:
        interval = _env_int("LOG_WS_PRIVACY_REFRESH_INTERVAL_SECONDS", 3600, 60)
        while not self._stop.is_set():
            await asyncio.sleep(interval)
            conn = connect()
            try:
                result = await refresh_due_profiles(conn, limit=_env_int("PRIVACY_REFRESH_BATCH", 100, 1))
                if result.get("processed"):
                    await bus.publish("ip_changes", {"cursor": 0, "count": result["processed"]})
            except asyncio.CancelledError:
                raise
            except Exception:
                conn.rollback()
            finally:
                conn.close()

    async def correlation_loop(self) -> None:
        interval = _env_int("LOG_WS_CORRELATION_INTERVAL_SECONDS", 3600, 300)
        while not self._stop.is_set():
            await asyncio.sleep(interval)
            conn = connect()
            try:
                result = await asyncio.to_thread(asn_clusters, conn, None, _env_int("CORRELATION_OVERLAP_MINUTES", 10, 1))
                if result:
                    await bus.publish("ip_changes", {"cursor": 0, "count": len(result)})
            except asyncio.CancelledError:
                raise
            except Exception:
                conn.rollback()
            finally:
                conn.close()

    def _run_ai_train(self) -> dict[str, Any]:
        conn = connect()
        try:
            return train_model(conn, self._fit_executor)
        finally:
            conn.close()

    async def ai_loop(self) -> None:
        while not self._stop.is_set():
            await asyncio.sleep(self.config.ai_interval_seconds)
            try:
                if not await asyncio.to_thread(self._acquire_ai_lease):
                    continue
                async with self._ai_lock:
                    conn = connect()
                    try:
                        state = conn.execute("SELECT trained_at FROM ai_model_state WHERE model_key=?", ("isolation_forest_v1",)).fetchone()
                    finally:
                        conn.close()
                    trained_at = None
                    if state and state["trained_at"]:
                        try:
                            trained_at = datetime.fromisoformat(state["trained_at"])
                        except ValueError:
                            trained_at = None
                    train_interval = _env_int("LOG_WS_AI_TRAIN_INTERVAL_SECONDS", 21600, 300)
                    should_train = load_model_bundle() is None or trained_at is None or (_utc_datetime() - trained_at).total_seconds() >= train_interval
                    force_full = False
                    if should_train:
                        trained = await asyncio.to_thread(self._run_ai_train)
                        self.ai_status["training"] = trained
                        await bus.publish("ai_trained", {**trained, "last_run": utc_now()})
                        force_full = trained.get("status") == "trained"
                    conn = connect()
                    try:
                        scored = await asyncio.to_thread(score_cycle, conn, force_full)
                        trim_change_log(conn)
                        conn.commit()
                    finally:
                        conn.close()
                    self.ai_status["scoring"] = scored
                    self.ai_last_run = utc_now()
                    await bus.publish("ai_scored", {**scored, "last_run": self.ai_last_run})
                    if scored.get("changed_ips"):
                        await bus.publish("ip_changes", {"cursor": scored.get("cursor", 0), "count": scored["changed_ips"]})
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.ai_status = {"status": "failed", "error": type(exc).__name__}
                await bus.publish("ai_scored", self.ai_status)
            finally:
                await asyncio.to_thread(self._release_ai_lease)


def _utc_datetime() -> datetime:
    return datetime.now(timezone.utc)


collector = WebSocketCollector()
