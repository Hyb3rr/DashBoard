"""Low-overhead process metrics updated at batch and health boundaries."""
from __future__ import annotations

from collections import defaultdict
from threading import Lock
from time import perf_counter

_lock = Lock()
_counters: dict[str, int] = defaultdict(int)
_gauges: dict[str, float] = {}
_timings: dict[str, dict[str, float]] = defaultdict(lambda: {"count": 0, "total_ms": 0.0, "last_ms": 0.0})


def increment(name: str, value: int = 1) -> None:
    with _lock:
        _counters[name] += value


def gauge(name: str, value: int | float) -> None:
    with _lock:
        _gauges[name] = float(value)


def observe(name: str, elapsed_ms: float) -> None:
    with _lock:
        item = _timings[name]
        item["count"] += 1
        item["total_ms"] += elapsed_ms
        item["last_ms"] = elapsed_ms


def timed(name: str):
    started = perf_counter()

    def finish() -> None:
        observe(name, (perf_counter() - started) * 1000)

    return finish


def snapshot() -> dict:
    with _lock:
        return {
            "counters": dict(_counters),
            "gauges": dict(_gauges),
            "timings": {key: {**value, "avg_ms": value["total_ms"] / value["count"] if value["count"] else 0.0}
                         for key, value in _timings.items()},
        }
