#!/usr/bin/env python3
"""Native ingest -> durable state -> PostgreSQL notify -> SSE probe."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid

import httpx
import psycopg
import websockets


PROJECT = Path(__file__).resolve().parents[2]
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))


def pg_value(dsn: str, query: str, params: tuple = ()):
    with psycopg.connect(dsn, autocommit=True) as conn:
        return conn.execute(query, params).fetchone()[0]


def pg_ip_change(dsn: str, cursor: int, ip: str) -> dict | None:
    """Resolve an SSE cursor to the exact change-feed row for the fixture IP."""
    with psycopg.connect(dsn, autocommit=True) as conn:
        row = conn.execute(
            """SELECT seq, host(ip) AS ip
               FROM ip_change_log
              WHERE seq = %s AND ip = %s::inet""",
            (cursor, ip),
        ).fetchone()
    if row is None:
        return None
    return {"seq": int(row[0]), "ip": str(row[1])}


def cleanup_pg(dsn: str, source_id: str, ip: str) -> None:
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("DELETE FROM ip_change_log WHERE ip = %s::inet", (ip,))
        conn.execute("DELETE FROM ip_observations_state WHERE ip = %s::inet", (ip,))
        conn.execute("DELETE FROM ip_profiles WHERE ip = %s::inet", (ip,))
        conn.execute("DELETE FROM processed_batches WHERE source_id = %s", (source_id,))
        conn.execute("DELETE FROM log_sources WHERE source_id = %s", (source_id,))


def cleanup_ch(source_id: str) -> None:
    from app.db import clickhouse

    client = clickhouse.connect()
    try:
        client.command("ALTER TABLE ipintel.http_events DELETE WHERE source_id = {source:String}", {"source": source_id})
    finally:
        client.close()


def ch_count(source_id: str, ip: str) -> int:
    from app.db import clickhouse

    client = clickhouse.connect()
    try:
        result = client.query(
            "SELECT count() FROM http_events WHERE source_id = {source:String} AND src_ip = {ip:IPv6}",
            parameters={"source": source_id, "ip": ip},
        )
        return int(result.result_rows[0][0])
    finally:
        client.close()


async def wait_http(url: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    async with httpx.AsyncClient(timeout=2.0, trust_env=False) as client:
        while time.monotonic() < deadline:
            try:
                response = await client.get(url)
                if response.status_code in {200, 401}:
                    return
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0.2)
    raise RuntimeError(f"runtime did not become reachable: {url}")


async def run_probe(args: argparse.Namespace) -> dict:
    dsn = os.environ["POSTGRES_DSN"]
    source_id = f"e2e-probe-{uuid.uuid4().hex[:12]}"
    ip = "192.0.2.241"
    line = f'192.0.2.241 - - [15/Sep/2026:17:00:00 +0000] "GET /e2e-probe HTTP/1.1" 200 17 "-" "sentinel-e2e-probe"'
    final_offset = len(line.encode("utf-8")) + 1
    released = asyncio.Event()
    connected = asyncio.Event()

    async def ws_handler(websocket):
        connected.set()
        await released.wait()
        await websocket.send(json.dumps({"type": "backlog_done"}))
        await websocket.send(json.dumps({"type": "lines", "items": [line]}))
        await websocket.send(json.dumps({"type": "offset", "value": final_offset}))
        await asyncio.sleep(3)

    env = os.environ.copy()
    env.update({
        "APP_ROLE": "all",
        "LOG_WS_ENABLED": "true",
        "LOG_WS_URL": f"ws://127.0.0.1:{args.websocket_port}/log-ws",
        "LOG_WS_TOKEN": "e2e-probe-token",
        "LOG_WS_SOURCE_ID": source_id,
        "LOG_WS_LOG_KEY": "access",
        "LOG_WS_BATCH_SIZE": "1",
        "LOG_WS_FLUSH_MS": "50",
        "TRUSTED_HOSTS": "127.0.0.1,localhost",
    })
    process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(args.http_port)],
        cwd=PROJECT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        async with websockets.serve(ws_handler, "127.0.0.1", args.websocket_port):
            await wait_http(f"http://127.0.0.1:{args.http_port}/health")
            await asyncio.wait_for(connected.wait(), timeout=30)
            baseline = int(pg_value(dsn, "SELECT COALESCE(MAX(seq), 0) FROM ip_change_log"))
            released.set()
            deadline = time.monotonic() + args.timeout
            captured: list[dict] = []
            bound_change: dict | None = None
            async with httpx.AsyncClient(timeout=httpx.Timeout(connect=5, read=5, write=5, pool=5), trust_env=False) as client:
                async with client.stream("GET", f"http://127.0.0.1:{args.http_port}/api/stream", headers={"Accept": "text/event-stream"}) as response:
                    response.raise_for_status()
                    event_name = None
                    async for raw_line in response.aiter_lines():
                        if time.monotonic() >= deadline:
                            break
                        if raw_line.startswith("event: "):
                            event_name = raw_line[7:]
                        elif raw_line.startswith("data: ") and event_name == "ip_changes":
                            payload = json.loads(raw_line[6:])
                            if int(payload.get("cursor", 0)) > baseline:
                                captured.append(payload)
                                bound_change = pg_ip_change(dsn, int(payload["cursor"]), ip)
                                if bound_change is not None:
                                    break
                        elif not raw_line:
                            event_name = None

            checkpoint = int(pg_value(dsn, "SELECT last_offset FROM log_sources WHERE source_id = %s", (source_id,)))
            pg_ip_count = int(pg_value(dsn, "SELECT COUNT(*) FROM ip_observations_state WHERE ip = %s::inet", (ip,)))
            events_in_ch = ch_count(source_id, ip)
            result = {
                "source_id": source_id,
                "baseline_cursor": baseline,
                "captured_sse_events": captured,
                "checkpoint": checkpoint,
                "expected_checkpoint": final_offset,
                "pg_observation_rows": pg_ip_count,
                "clickhouse_events": events_in_ch,
                "bound_ip_change": bound_change,
                "source_binding": {
                    "source_id": source_id,
                    "checkpoint_matches_fixture": checkpoint == final_offset,
                    "observation_matches_fixture": pg_ip_count >= 1,
                },
            }
            cursor_bound_to_fixture = (
                bound_change is not None
                and bound_change["ip"] == ip
            )
            if (
                checkpoint != final_offset
                or pg_ip_count < 1
                or events_in_ch < 1
                or not captured
                or not cursor_bound_to_fixture
            ):
                raise RuntimeError(json.dumps(result, sort_keys=True))
            print(json.dumps(result, indent=2, sort_keys=True))
            return result
    finally:
        released.set()
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        try:
            cleanup_ch(source_id)
            cleanup_pg(dsn, source_id, ip)
        except Exception as exc:
            print(f"cleanup warning: {type(exc).__name__}: {exc}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--http-port", type=int, default=8011)
    parser.add_argument("--websocket-port", type=int, default=8791)
    parser.add_argument("--timeout", type=float, default=45.0)
    args = parser.parse_args()
    if not os.getenv("POSTGRES_DSN"):
        parser.error("POSTGRES_DSN is required")
    asyncio.run(run_probe(args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
