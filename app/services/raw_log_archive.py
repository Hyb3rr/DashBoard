"""Lossless, asynchronous raw WebSocket payload spool with sealed chunks."""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import time

from ..core import metrics
from app.config.backup import BackupSettings
from .raw_archive_compression import (
    RawArchiveCompressionError,
    compress_and_verify,
    write_compression_marker,
)
from .raw_archive_upload import (
    RawArchiveUploadError,
    azure_sdk_available,
    create_azure_uploader,
    remove_uploaded_artifacts,
    upload_sealed,
)


DEFAULT_SPOOL_DIR = Path(__file__).resolve().parents[2] / "data" / "raw-log-spool"
DEFAULT_MAX_CHUNK_BYTES = 128 * 1024 * 1024
_SAFE_SOURCE = re.compile(r"[^A-Za-z0-9_.-]+")
_CHUNK_ID = re.compile(r"^(?P<hour>\d{8}T\d{6}Z)-(?P<sequence>\d{6})$")
DEFAULT_QUEUE_MAX_LINES = 10000
DEFAULT_QUEUE_MAX_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_WRITE_ATTEMPTS = 5
DEFAULT_WRITE_BACKOFF_SECONDS = 0.25
DEFAULT_WRITE_BACKOFF_MAX_SECONDS = 10.0


class RawArchivePressure(RuntimeError):
    """Admission refused so the caller can reconnect/replay instead of dropping."""


class RawArchiveWriteError(RuntimeError):
    """Raw persistence failed after the bounded retry policy was exhausted."""


@dataclass(frozen=True)
class RawDurableReceipt:
    source_id: str
    group_id: str
    line_count: int
    raw_bytes: int
    chunk_id: str | None
    status: str = "RAW_DURABLE"


@dataclass
class _ActiveChunk:
    chunk_id: str
    started_at: datetime
    hour: str
    path: Path
    metadata_path: Path
    line_count: int = 0
    raw_bytes: int = 0


@dataclass(frozen=True)
class _RawArchiveItem:
    line: str
    received_at: datetime
    receipt: asyncio.Future | None = None
    is_last: bool = False
    group_id: str = "legacy"


class RawLogArchive:
    """Queue raw lines immediately; one background task writes and seals chunks."""

    def __init__(self, source_id: str, spool_dir: str | Path | None = None,
                 max_chunk_bytes: int = DEFAULT_MAX_CHUNK_BYTES,
                 max_queue_lines: int = DEFAULT_QUEUE_MAX_LINES,
                 max_queue_bytes: int = DEFAULT_QUEUE_MAX_BYTES,
                 max_write_attempts: int | None = None,
                 write_backoff_seconds: float | None = None) -> None:
        """Initialize archive paths, bounded queues, counters, and receipt state."""
        if max_chunk_bytes <= 0:
            raise ValueError("raw archive max chunk bytes must be positive")
        if max_queue_lines <= 0 or max_queue_bytes <= 0:
            raise ValueError("raw archive queue limits must be positive")
        self.source_id = source_id
        self.spool_dir = Path(spool_dir or os.getenv("RAW_LOG_ARCHIVE_SPOOL_DIR", str(DEFAULT_SPOOL_DIR)))
        self.max_chunk_bytes = max_chunk_bytes
        self.max_queue_lines = max_queue_lines
        self.max_queue_bytes = max_queue_bytes
        self.max_write_attempts = max_write_attempts or int(os.getenv(
            "RAW_ARCHIVE_MAX_WRITE_ATTEMPTS", str(DEFAULT_MAX_WRITE_ATTEMPTS)
        ))
        self.write_backoff_seconds = write_backoff_seconds if write_backoff_seconds is not None else float(
            os.getenv("RAW_ARCHIVE_WRITE_BACKOFF_SECONDS", str(DEFAULT_WRITE_BACKOFF_SECONDS))
        )
        if self.max_write_attempts <= 0 or self.write_backoff_seconds < 0:
            raise ValueError("raw archive retry settings must be non-negative and attempts must be positive")
        self._queue: asyncio.Queue[_RawArchiveItem] = asyncio.Queue(maxsize=max_queue_lines)
        self._queued_stamps: deque[datetime] = deque()
        self._task: asyncio.Task | None = None
        self._compression_task: asyncio.Task | None = None
        self._upload_task: asyncio.Task | None = None
        self._stop = False
        self._active: _ActiveChunk | None = None
        self._next_sequence = 1
        self._written_lines = 0
        self._written_bytes = 0
        self._pending_bytes = 0
        self._sealed_chunks = 0
        self._failed_writes = 0
        self._last_error: str | None = None
        self._pressure_state = "NORMAL"
        self._compressed_chunks = 0
        self._compression_failures = 0
        self._compression_status = "PENDING"
        self._uploaded_chunks = 0
        self._upload_failures = 0
        self._upload_status = "PENDING"
        self._receipt_sequence = 0
        self._last_receipt: RawDurableReceipt | None = None
        self._receipt_groups: dict[str, tuple[int, int]] = {}
        self._stop_lock = asyncio.Lock()
        self._stopped = False
        self._writer_status = "READY"
        self._consecutive_write_failures = 0
        self._write_retry_count = 0

    async def start(self) -> None:
        """Start archive writer and background compression/upload consumers."""
        if self._task and not self._task.done():
            return
        await asyncio.to_thread(self.spool_dir.mkdir, parents=True, exist_ok=True)
        await asyncio.to_thread(self._advance_sequence)
        await asyncio.to_thread(self._recover_active)
        self._stop = False
        self._stopped = False
        self._writer_status = "READY"
        self._consecutive_write_failures = 0
        self._task = asyncio.create_task(self._writer_loop(), name="raw-log-archive")
        if shutil.which("zstd"):
            if not self._compression_task or self._compression_task.done():
                self._compression_status = "READY"
                self._compression_task = asyncio.create_task(
                    self._compression_loop(), name="raw-log-zstd"
                )
        else:
            self._compression_status = "UNAVAILABLE"
            self._last_error = "zstd executable is unavailable; no compression fallback is used"
        try:
            BackupSettings.from_env()
        except RuntimeError:
            self._upload_status = "UNAVAILABLE"
        else:
            if not self._upload_task or self._upload_task.done():
                self._upload_status = "READY"
                self._upload_task = asyncio.create_task(self._upload_loop(), name="raw-log-azure")

    def tap(self, lines: list[str], received_at: datetime | None = None) -> int:
        """Queue raw text immediately; never performs disk or network I/O."""
        if self._writer_status == "FAILED":
            raise RawArchiveWriteError(self._last_error or "raw archive writer is failed")
        stamp = received_at or datetime.now(timezone.utc)
        valid = [line for line in lines if isinstance(line, str)]
        requested_bytes = sum(len(line.encode("utf-8")) + 1 for line in valid)
        if (self._queue.qsize() + len(valid) > self.max_queue_lines or
                self._pending_bytes + requested_bytes > self.max_queue_bytes):
            self._pressure_state = "CRITICAL"
            self._last_error = "raw archive queue capacity reached; reconnect required for replay"
            metrics.increment("raw_archive.admission_pressure")
            self._update_metrics()
            raise RawArchivePressure(self._last_error)
        for line in valid:
            self._queue.put_nowait(_RawArchiveItem(line, stamp))
            self._queued_stamps.append(stamp)
        if valid:
            self._pending_bytes += requested_bytes
        self._update_metrics()
        return len(valid)

    async def append_batch(self, lines: list[str], received_at: datetime | None = None) -> RawDurableReceipt:
        """Append one admitted group and resolve only after one group fsync."""
        if self._writer_status == "FAILED":
            await self.start()
            if self._writer_status == "FAILED":
                raise RawArchiveWriteError(self._last_error or "raw archive writer is failed")
        archive_started = bool(self._task and not self._task.done())
        valid = [line for line in lines if isinstance(line, str)]
        if not valid:
            return RawDurableReceipt(self.source_id, "empty", 0, 0, None)
        stamp = received_at or datetime.now(timezone.utc)
        requested_bytes = sum(len(line.encode("utf-8")) + 1 for line in valid)
        if (self._queue.qsize() + len(valid) > self.max_queue_lines or
                self._pending_bytes + requested_bytes > self.max_queue_bytes):
            self._pressure_state = "CRITICAL"
            self._last_error = "raw archive queue capacity reached; reconnect required for replay"
            self._update_metrics()
            raise RawArchivePressure(self._last_error)
        self._receipt_sequence += 1
        group_id = f"{self.source_id}-{self._receipt_sequence:08d}"
        if not archive_started:
            for line in valid:
                await asyncio.to_thread(self._write_line, line, stamp)
            await asyncio.to_thread(self._sync_active)
            return RawDurableReceipt(
                self.source_id, group_id, len(valid), requested_bytes,
                self._active.chunk_id if self._active else None,
            )
        self._receipt_groups[group_id] = (len(valid), requested_bytes)
        loop = asyncio.get_running_loop()
        receipt_future = loop.create_future()
        for index, line in enumerate(valid):
            self._queue.put_nowait(_RawArchiveItem(
                line, stamp, receipt_future, index == len(valid) - 1, group_id,
            ))
            self._queued_stamps.append(stamp)
        self._pending_bytes += requested_bytes
        self._update_metrics()
        return await receipt_future

    def pending_bytes(self) -> int:
        """Return the total bytes currently waiting for archive persistence."""
        return self._pending_bytes

    def status(self) -> dict[str, int | str | None]:
        """Expose archive health, backlog, spool, and upload status."""
        self._update_metrics()
        return {
            "pending_lines": self._queue.qsize(),
            "pending_bytes": self._pending_bytes,
            "written_lines": self._written_lines,
            "written_bytes": self._written_bytes,
            "sealed_chunks": self._sealed_chunks,
            "active_chunk": self._active.chunk_id if self._active else None,
            "active_chunk_bytes": self._active.raw_bytes if self._active else 0,
            "failed_writes": self._failed_writes,
            "last_error": self._last_error,
            "queue_capacity_lines": self.max_queue_lines,
            "queue_capacity_bytes": self.max_queue_bytes,
            "pressure_state": self._pressure_state,
            "oldest_queued_age_seconds": self._oldest_queued_age_seconds(),
            "writer_lag_seconds": self._oldest_queued_age_seconds(),
            "compression_status": self._compression_status,
            "compressed_chunks": self._compressed_chunks,
            "compression_failures": self._compression_failures,
            "upload_status": self._upload_status,
            "uploaded_chunks": self._uploaded_chunks,
            "upload_failures": self._upload_failures,
            "writer_status": self._writer_status,
            "consecutive_write_failures": self._consecutive_write_failures,
            "write_retry_count": self._write_retry_count,
        }

    @staticmethod
    def _fail_receipt(receipt: asyncio.Future | None, error: Exception) -> None:
        """Complete a durability receipt with its associated write failure."""
        if receipt is not None and not receipt.done():
            receipt.set_exception(error)

    def _fail_queued_items(self, error: Exception, current: _RawArchiveItem | None = None) -> None:
        """Fail every queued durability receipt after writer termination."""
        self._fail_receipt(current.receipt if current else None, error)
        if current:
            self._receipt_groups.pop(current.group_id, None)
        while True:
            try:
                item = self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            else:
                self._fail_receipt(item.receipt, error)
                self._receipt_groups.pop(item.group_id, None)
                self._queue.task_done()
        self._queued_stamps.clear()
        self._pending_bytes = 0

    def _oldest_queued_age_seconds(self) -> float:
        """Measure the age of the oldest queued archive item."""
        if not self._queued_stamps:
            return 0.0
        return round(max(0.0, time.time() - self._queued_stamps[0].timestamp()), 3)

    def _source_name(self) -> str:
        """Return the normalized archive source identifier."""
        return _SAFE_SOURCE.sub("_", self.source_id).strip("._") or "source"

    def _directory(self, stamp: datetime) -> Path:
        """Resolve and create the archive directory for a data category."""
        day = stamp.astimezone(timezone.utc)
        return self.spool_dir / self._source_name() / f"{day:%Y}" / f"{day:%m}" / f"{day:%d}"

    def _new_active(self, stamp: datetime) -> _ActiveChunk:
        """Create a new active raw-log chunk and its metadata state."""
        stamp = stamp.astimezone(timezone.utc)
        hour = stamp.strftime("%Y%m%dT%H0000Z")
        chunk_id = f"{hour}-{self._next_sequence:06d}"
        self._next_sequence += 1
        directory = self._directory(stamp)
        return _ActiveChunk(
            chunk_id=chunk_id, started_at=stamp, hour=hour,
            path=directory / f"{chunk_id}.active",
            metadata_path=directory / f"{chunk_id}.active.json",
        )

    def _recover_active(self) -> None:
        """Recover or quarantine an unfinished active chunk after restart."""
        candidates = sorted(self.spool_dir.rglob("*.active.json"))
        if not candidates:
            return
        candidate = candidates[-1]
        try:
            metadata = json.loads(candidate.read_text())
            chunk_id = str(metadata["chunk_id"])
            match = _CHUNK_ID.fullmatch(chunk_id)
            if not match:
                raise ValueError("invalid chunk id")
            path = candidate.with_name(f"{chunk_id}.active")
            if not path.is_file():
                return
            payload = path.read_bytes()
            complete = payload.rfind(b"\n") + 1
            if complete != len(payload):
                path.write_bytes(payload[:complete])
                payload = payload[:complete]
            stamp = datetime.fromisoformat(str(metadata["started_at"]))
            self._active = _ActiveChunk(
                chunk_id=chunk_id, started_at=stamp, hour=match.group("hour"),
                path=path, metadata_path=candidate,
                line_count=payload.count(b"\n"), raw_bytes=len(payload),
            )
            self._next_sequence = max(self._next_sequence, int(match.group("sequence")) + 1)
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            self._last_error = f"cannot recover active raw archive chunk: {candidate.name}"

    def _advance_sequence(self) -> None:
        """Advance the source sequence using the accepted raw lines."""
        for path in self.spool_dir.rglob("*"):
            if path.suffix not in {".log", ".active"}:
                continue
            match = _CHUNK_ID.fullmatch(path.stem)
            if match:
                self._next_sequence = max(self._next_sequence, int(match.group("sequence")) + 1)

    def _write_active_metadata(self) -> None:
        """Persist the active chunk manifest and sequence metadata."""
        assert self._active
        metadata = {
            "source": self.source_id, "chunk_id": self._active.chunk_id,
            "started_at": self._active.started_at.isoformat(), "ended_at": None,
            "line_count": self._active.line_count, "raw_bytes": self._active.raw_bytes,
            "path": str(self._active.path), "status": "ACTIVE",
        }
        temporary = self._active.metadata_path.with_suffix(".active.json.tmp")
        temporary.write_text(json.dumps(metadata, indent=2) + "\n")
        temporary.replace(self._active.metadata_path)

    def _seal_active(self, ended_at: datetime) -> None:
        """Flush and seal a completed active chunk for compression."""
        active = self._active
        if not active:
            return
        sealed_path = active.path.with_suffix(".log")
        self._sync_path(active.path)
        active.path.replace(sealed_path)
        metadata = {
            "source": self.source_id, "chunk_id": active.chunk_id,
            "started_at": active.started_at.isoformat(),
            "ended_at": ended_at.astimezone(timezone.utc).isoformat(),
            "line_count": active.line_count, "raw_bytes": active.raw_bytes,
            "path": str(sealed_path), "status": "SEALED",
        }
        sealed_metadata = active.metadata_path.with_name(f"{active.chunk_id}.json")
        temporary = sealed_metadata.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(metadata, indent=2) + "\n")
        self._sync_path(temporary)
        temporary.replace(sealed_metadata)
        self._sync_directory(sealed_path.parent)
        if active.metadata_path.exists():
            active.metadata_path.unlink()
        self._sealed_chunks += 1
        self._active = None

    def _write_line(self, line: str, received_at: datetime) -> None:
        """Append one raw line and update its chunk integrity metadata."""
        stamp = received_at.astimezone(timezone.utc)
        payload = line.encode("utf-8") + b"\n"
        if self._active and (self._active.hour != stamp.strftime("%Y%m%dT%H0000Z") or
                             self._active.raw_bytes + len(payload) > self.max_chunk_bytes):
            self._seal_active(stamp)
        if not self._active:
            self._active = self._new_active(stamp)
            self._active.path.parent.mkdir(parents=True, exist_ok=True)
            self._write_active_metadata()
        with self._active.path.open("ab") as stream:
            stream.write(payload)
        self._active.line_count += 1
        self._active.raw_bytes += len(payload)
        self._write_active_metadata()
        self._written_lines += 1
        self._written_bytes += len(payload)

    def _sync_active(self) -> None:
        """Flush and fsync the active chunk before acknowledging durability."""
        if not self._active:
            return
        self._sync_path(self._active.path)

    @staticmethod
    def _sync_path(path: Path) -> None:
        """Fsync a file path when the platform supports it."""
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _sync_directory(path: Path) -> None:
        """Fsync a directory so archive metadata changes are durable."""
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _write_parse_failures(self, records: list[dict]) -> None:
        """Persist parser rejection evidence as a separate archive artifact."""
        if not records:
            return
        active = self._active
        if not active:
            raise RuntimeError("cannot quarantine parse failures without an active raw chunk")
        path = active.path.with_name(f"{active.chunk_id}.parse-failures.jsonl")
        existing = set()
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                try:
                    item = json.loads(line)
                    existing.add((item.get("source_offset"), item.get("raw_sha256"), item.get("parser_error_code")))
                except json.JSONDecodeError:
                    raise RuntimeError(f"parse-failure sidecar is malformed: {path.name}")
        with path.open("a", encoding="utf-8") as stream:
            for record in records:
                key = (record.get("source_offset"), record.get("raw_sha256"), record.get("parser_error_code"))
                if key not in existing:
                    stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
                    existing.add(key)
            stream.flush()
            os.fsync(stream.fileno())

    def write_parse_failures(self, records: list[dict]) -> None:
        """Queue parse-failure evidence for durable archive persistence."""
        self._write_parse_failures(records)

    async def _writer_loop(self) -> None:
        """Persist queued raw lines and resolve receipts after fsync."""
        while not self._stop or not self._queue.empty():
            try:
                item = await asyncio.wait_for(self._queue.get(), timeout=0.5)
                self._queued_stamps.popleft()
            except asyncio.TimeoutError:
                continue
            payload_size = len(item.line.encode("utf-8")) + 1
            try:
                for attempt in range(1, self.max_write_attempts + 1):
                    try:
                        await asyncio.to_thread(self._write_line, item.line, item.received_at)
                        self._consecutive_write_failures = 0
                        self._writer_status = "READY"
                        break
                    except Exception as exc:
                        self._failed_writes += 1
                        self._consecutive_write_failures += 1
                        self._last_error = f"{type(exc).__name__}: {exc}"[:240]
                        metrics.increment("raw_archive.write_failures")
                        if attempt >= self.max_write_attempts:
                            error = RawArchiveWriteError(
                                f"raw archive write failed after {attempt} attempts: {self._last_error}"
                            )
                            self._writer_status = "FAILED"
                            metrics.increment("raw_archive.terminal_write_failures")
                            self._fail_queued_items(error, current=item)
                            return
                        self._writer_status = "RETRYING"
                        self._write_retry_count += 1
                        await asyncio.sleep(min(
                            self.write_backoff_seconds * (2 ** (attempt - 1)),
                            DEFAULT_WRITE_BACKOFF_MAX_SECONDS,
                        ))
                self._pending_bytes -= payload_size
                if item.receipt is not None and item.is_last:
                    await asyncio.to_thread(self._sync_active)
                    group_lines, group_bytes = self._receipt_groups.pop(item.group_id)
                    receipt = RawDurableReceipt(
                        self.source_id, item.group_id,
                        group_lines,
                        group_bytes,
                        self._active.chunk_id if self._active else None,
                    )
                    self._last_receipt = receipt
                    if not item.receipt.done():
                        item.receipt.set_result(receipt)
                self._last_error = None
                if self._queue.qsize() == 0:
                    self._pressure_state = "NORMAL"
            finally:
                self._queue.task_done()
                self._update_metrics()

    def _sealed_paths(self) -> list[Path]:
        """List sealed archive chunks that are ready for processing."""
        return sorted(
            path for path in self.spool_dir.rglob("*.log")
            if _CHUNK_ID.fullmatch(path.stem) and not path.with_suffix(".log.zst").exists()
        )

    @staticmethod
    def _compress_and_verify(path: Path) -> dict:
        """Compress a sealed chunk and verify its checksum and line count."""
        return compress_and_verify(path)

    async def _compression_loop(self) -> None:
        """Compress sealed chunks from the bounded background queue."""
        while True:
            paths = await asyncio.to_thread(self._sealed_paths)
            if not paths:
                if self._stop:
                    return
                await asyncio.sleep(0.5)
                continue
            for path in paths:
                try:
                    result = await asyncio.to_thread(self._compress_and_verify, path)
                    await asyncio.to_thread(self._write_compression_marker, path, result)
                    self._compressed_chunks += 1
                    self._compression_status = "READY"
                except Exception as exc:
                    self._compression_failures += 1
                    self._compression_status = "ERROR"
                    self._last_error = f"{type(exc).__name__}: {exc}"[:240]
                    metrics.increment("raw_archive.compression_failures")
                    if not self._stop:
                        await asyncio.sleep(1)
                        break
                finally:
                    self._update_metrics()
            if self._stop:
                return

    @staticmethod
    def _upload_sealed(path: Path, spool_dir: Path, source_id: str,
                       settings: BackupSettings, uploader, verifier) -> dict:
        """Upload a verified sealed chunk and write its remote manifest."""
        return upload_sealed(path, spool_dir, source_id, settings, uploader, verifier)

    async def _upload_loop(self) -> None:
        """Upload verified archive chunks from the background queue."""
        dependencies = self._initialize_uploader()
        if dependencies is None:
            return
        settings, uploader, verifier = dependencies
        try:
            while True:
                paths = await asyncio.to_thread(self._upload_paths)
                if not paths:
                    if self._stop:
                        return
                    await asyncio.sleep(0.5)
                    continue
                await self._upload_paths_once(paths, settings, uploader, verifier)
                if self._stop:
                    return
        finally:
            uploader.close()

    def _initialize_uploader(self):
        """Load Azure upload dependencies and record unavailable startup states."""
        try:
            settings = BackupSettings.from_env()
            settings = BackupSettings(settings.account, settings.container, settings.auth,
                                      settings.tenant_id, settings.client_id, settings.client_secret,
                                      settings.prefix, settings.part_size, settings.endpoint)
        except RuntimeError as exc:
            self._upload_status = "UNAVAILABLE"
            self._last_error = str(exc)[:240]
            return None
        if not azure_sdk_available():
            self._upload_status = "UNAVAILABLE"
            self._last_error = "Azure SDK is unavailable; raw archive upload is disabled"
            return None
        try:
            uploader, verifier = create_azure_uploader(settings)
        except Exception as exc:
            self._upload_status = "ERROR"
            self._last_error = f"{type(exc).__name__}: {exc}"[:240]
            self._upload_failures += 1
            return None
        return settings, uploader, verifier

    async def _upload_paths_once(self, paths: list[Path], settings: BackupSettings,
                                 uploader, verifier) -> None:
        """Upload one discovered path batch and pause after the first failure."""
        for path in paths:
            try:
                await asyncio.to_thread(
                    self._upload_sealed, path, self.spool_dir, self.source_id,
                    settings, uploader, verifier,
                )
                await asyncio.to_thread(self._remove_uploaded_artifacts, path)
                self._uploaded_chunks += 1
                self._upload_status = "READY"
            except Exception as exc:
                self._upload_failures += 1
                self._upload_status = "ERROR"
                self._last_error = f"{type(exc).__name__}: {exc}"[:240]
                metrics.increment("raw_archive.upload_failures")
                if not self._stop:
                    await asyncio.sleep(1)
                    break
            finally:
                self._update_metrics()

    def _upload_paths(self) -> list[Path]:
        """Queue sealed archive paths for remote upload."""
        return sorted(
            path for path in self.spool_dir.rglob("*.log.zst")
            if path.with_name(path.name + ".json").is_file()
        )

    @staticmethod
    def _remove_uploaded_artifacts(path: Path) -> None:
        """Remove local artifacts only after successful remote upload."""
        remove_uploaded_artifacts(path)

    def _update_metrics(self) -> None:
        """Refresh observable counters and gauges for archive operations."""
        metrics.gauge("raw_archive.queue_lines", self._queue.qsize())
        metrics.gauge("raw_archive.queue_bytes", self._pending_bytes)
        ratio = max(self._queue.qsize() / self.max_queue_lines, self._pending_bytes / self.max_queue_bytes)
        if self._pressure_state != "CRITICAL":
            self._pressure_state = "PRESSURE" if ratio >= 0.7 else "NORMAL"
        metrics.gauge("raw_archive.queue_capacity_lines", self.max_queue_lines)
        metrics.gauge("raw_archive.queue_capacity_bytes", self.max_queue_bytes)
        metrics.gauge("raw_archive.writer_lag_seconds", self._oldest_queued_age_seconds())

    async def stop(self) -> None:
        """Drain archive work and stop background consumers safely."""
        async with self._stop_lock:
            if self._stopped and not self._task and not self._compression_task and not self._upload_task:
                return
            self._stop = True
            if self._task:
                await self._task
                if self._active:
                    await asyncio.to_thread(self._seal_active, datetime.now(timezone.utc))
                self._task = None
            if self._compression_task:
                await self._compression_task
                self._compression_task = None
                if await asyncio.to_thread(self._sealed_paths) and shutil.which("zstd"):
                    self._stop = True
                    self._compression_task = asyncio.create_task(self._compression_loop(), name="raw-log-zstd-finalize")
                    await self._compression_task
                    self._compression_task = None
            if self._upload_task:
                await self._upload_task
                self._upload_task = None
            self._stopped = True

    async def maintenance_once(self) -> dict:
        """Drain sealed local artifacts once, for an external locked scheduler."""
        self._stop = True
        if shutil.which("zstd"):
            self._compression_status = "READY"
            await self._compression_loop()
        else:
            self._compression_status = "UNAVAILABLE"
        if self._upload_status != "UNAVAILABLE":
            await self._upload_loop()
        return self.status()

    def _write_compression_marker(self, path: Path, result: dict) -> None:
        """Record compression state for a sealed archive chunk."""
        write_compression_marker(path, result, self.source_id)
