"""Low-overhead process metrics updated at batch and health boundaries."""
from __future__ import annotations

from collections import defaultdict
from threading import Lock
from time import perf_counter
import re

_lock = Lock()
_counters: dict[str, int] = defaultdict(int)
_gauges: dict[str, float] = {}
_timings: dict[str, dict[str, float]] = defaultdict(lambda: {"count": 0, "total_ms": 0.0, "last_ms": 0.0})


def increment(name: str, value: int = 1) -> None:
    """Add a value to a process-local counter."""
    with _lock:
        _counters[name] += value


def gauge(name: str, value: int | float) -> None:
    """Set a process-local gauge to its latest value."""
    with _lock:
        _gauges[name] = float(value)


def observe(name: str, elapsed_ms: float) -> None:
    """Record one elapsed-time observation in milliseconds."""
    with _lock:
        item = _timings[name]
        item["count"] += 1
        item["total_ms"] += elapsed_ms
        item["last_ms"] = elapsed_ms


def timed(name: str):
    """Return a callback that records elapsed time when invoked."""
    started = perf_counter()

    def finish() -> None:
        """Record the time elapsed since the timing callback was created."""
        observe(name, (perf_counter() - started) * 1000)

    return finish


def snapshot() -> dict:
    """Return a thread-safe copy of all process-local metrics."""
    with _lock:
        return {
            "counters": dict(_counters),
            "gauges": dict(_gauges),
            "timings": {key: {**value, "avg_ms": value["total_ms"] / value["count"] if value["count"] else 0.0}
                         for key, value in _timings.items()},
        }


def prometheus_text() -> str:
    """Render process metrics without labels or untrusted string values."""
    data = snapshot()
    lines: list[str] = []

    def name(value: str) -> str:
        """Convert a metric key to a safe Prometheus metric name."""
        return "sentinel_" + re.sub(r"[^a-zA-Z0-9_]", "_", value)

    for key, value in sorted(data["counters"].items()):
        lines.append(f"{name(key)}_total {int(value)}")
    for key, value in sorted(data["gauges"].items()):
        lines.append(f"{name(key)} {float(value)}")
    for key, timing in sorted(data["timings"].items()):
        metric = name(key)
        lines.extend([
            f"{metric}_count {int(timing['count'])}",
            f"{metric}_sum_ms {float(timing['total_ms'])}",
            f"{metric}_last_ms {float(timing['last_ms'])}",
        ])
    return "\n".join(lines) + ("\n" if lines else "")


def reset() -> None:
    """Clear process-local metrics between isolated tests."""
    with _lock:
        _counters.clear()
        _gauges.clear()
        _timings.clear()
