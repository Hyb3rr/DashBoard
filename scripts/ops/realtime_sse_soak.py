#!/usr/bin/env python3
"""Read-only SSE concurrency/soak probe for the native FastAPI runtime."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import time
from dataclasses import dataclass

import httpx


def publish_notifications(dsn: str, count: int) -> None:
    """Publish a bounded sequence of PostgreSQL realtime wake-up signals."""
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as connection:
        for cursor in range(1, count + 1):
            connection.execute("SELECT pg_notify(%s, %s)", ("sentinel_ip_changes", str(cursor)))


@dataclass
class ClientResult:
    connected: bool = False
    first_byte_ms: float | None = None
    heartbeats: int = 0
    events: int = 0
    ip_change_events: int = 0
    errors: int = 0
    closed: bool = False


async def consume(client_id: int, url: str, duration: float, result: ClientResult) -> None:
    """Consume one SSE stream and record connection and event observations."""
    started = time.perf_counter()
    try:
        timeout = httpx.Timeout(connect=10.0, read=None, write=10.0, pool=10.0)
        async with httpx.AsyncClient(timeout=timeout, trust_env=False) as client:
            async with client.stream("GET", url, headers={"Accept": "text/event-stream"}) as response:
                response.raise_for_status()
                result.connected = True
                lines = response.aiter_lines()
                while True:
                    remaining = duration - (time.perf_counter() - started)
                    if remaining <= 0:
                        break
                    try:
                        line = await asyncio.wait_for(lines.__anext__(), timeout=remaining)
                    except (asyncio.TimeoutError, StopAsyncIteration):
                        break
                    if result.first_byte_ms is None:
                        result.first_byte_ms = (time.perf_counter() - started) * 1000
                    if line.startswith(": heartbeat"):
                        result.heartbeats += 1
                    elif line.startswith("event:"):
                        result.events += 1
                        if line == "event: ip_changes":
                            result.ip_change_events += 1
    except (httpx.HTTPError, asyncio.TimeoutError):
        result.errors += 1
    finally:
        result.closed = True


async def main(args: argparse.Namespace) -> int:
    """Run concurrent SSE clients and print their aggregate soak results."""
    results = [ClientResult() for _ in range(args.clients)]
    tasks = [
        asyncio.create_task(consume(i, args.url, args.duration, result))
        for i, result in enumerate(results)
    ]
    if args.notify_count:
        warmup_deadline = time.perf_counter() + args.warmup_seconds
        while sum(item.connected for item in results) < args.clients and time.perf_counter() < warmup_deadline:
            await asyncio.sleep(0.05)
        await asyncio.to_thread(publish_notifications, args.dsn, args.notify_count)
    await asyncio.gather(*tasks)

    summary = {
        "url": args.url,
        "clients": args.clients,
        "duration_seconds": args.duration,
        "connected": sum(item.connected for item in results),
        "connection_errors": sum(item.errors for item in results),
        "closed": sum(item.closed for item in results),
        "heartbeats": sum(item.heartbeats for item in results),
        "events": sum(item.events for item in results),
        "ip_change_events": sum(item.ip_change_events for item in results),
        "clients_with_events": sum(item.events > 0 for item in results),
        "notifications_published": args.notify_count,
        "first_byte_ms": {
            "min": min((item.first_byte_ms for item in results if item.first_byte_ms is not None), default=None),
            "max": max((item.first_byte_ms for item in results if item.first_byte_ms is not None), default=None),
        },
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["connection_errors"] == 0 and summary["connected"] == args.clients else 1


def parse_args() -> argparse.Namespace:
    """Parse and validate bounded SSE soak parameters."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8000/api/stream")
    parser.add_argument("--clients", type=int, default=25)
    parser.add_argument("--duration", type=float, default=20.0)
    parser.add_argument("--notify-count", type=int, default=0)
    parser.add_argument("--warmup-seconds", type=float, default=5.0)
    parser.add_argument("--dsn", default=os.getenv("POSTGRES_DSN", ""))
    args = parser.parse_args()
    if args.clients < 1 or args.clients > 1000:
        parser.error("--clients must be between 1 and 1000")
    if args.duration <= 0 or args.duration > 3600:
        parser.error("--duration must be between 0 and 3600 seconds")
    if args.notify_count < 0 or args.notify_count > 10000:
        parser.error("--notify-count must be between 0 and 10000")
    if args.notify_count and not args.dsn:
        parser.error("--dsn or POSTGRES_DSN is required with --notify-count")
    if args.warmup_seconds <= 0 or args.warmup_seconds > 60:
        parser.error("--warmup-seconds must be between 0 and 60")
    return args


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main(parse_args())))
