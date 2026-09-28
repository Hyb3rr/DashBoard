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
    """Return the first scalar value from a PostgreSQL query."""
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
    """Remove only the PostgreSQL rows created by the synthetic probe."""
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("DELETE FROM ip_change_log WHERE ip = %s::inet", (ip,))
        conn.execute("DELETE FROM ip_observations_state WHERE ip = %s::inet", (ip,))
        conn.execute("DELETE FROM ip_profiles WHERE ip = %s::inet", (ip,))
        conn.execute("DELETE FROM processed_batches WHERE source_id = %s", (source_id,))
        conn.execute("DELETE FROM log_sources WHERE source_id = %s", (source_id,))


def cleanup_ch(source_id: str) -> None:
    """Remove the synthetic probe events from ClickHouse."""
    from app.db import clickhouse

    client = clickhouse.connect()
    try:
        client.command("ALTER TABLE ipintel.http_events DELETE WHERE source_id = {source:String}", {"source": source_id})
    finally:
        client.close()


def ch_count(source_id: str, ip: str) -> int:
    """Count ClickHouse events belonging to the probe source and IP."""
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
    """Wait until the local API responds to a health request."""
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


def _fixture_log() -> tuple[str, str, int]:
    """Build the deterministic raw log, fixture IP, and final source offset."""
    ip = "192.0.2.241"
    line = f'192.0.2.241 - - [15/Sep/2026:17:00:00 +0000] "GET /e2e-probe HTTP/1.1" 200 17 "-" "sentinel-e2e-probe"'
    return line, ip, len(line.encode("utf-8")) + 1


def _server_environment(args: argparse.Namespace, source_id: str) -> dict[str, str]:
    """Create the isolated local collector configuration for the probe."""
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
    return env


def _start_probe_server(args: argparse.Namespace, source_id: str) -> subprocess.Popen:
    """Start a local all-role FastAPI process configured for the fixture."""
    return subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(args.http_port)],
        cwd=PROJECT,
        env=_server_environment(args, source_id),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


async def _send_fixture(websocket, released: asyncio.Event, connected: asyncio.Event,
                        line: str, final_offset: int) -> None:
    """Send the ordered synthetic log, backlog marker, and source offset."""
    connected.set()
    await released.wait()
    await websocket.send(json.dumps({"type": "backlog_done"}))
    await websocket.send(json.dumps({"type": "lines", "items": [line]}))
    await websocket.send(json.dumps({"type": "offset", "value": final_offset}))
    await asyncio.sleep(3)


async def _capture_fixture_changes(dsn: str, url: str, baseline: int, ip: str,
                                   timeout: float) -> tuple[list[dict], dict | None]:
    """Capture post-baseline SSE cursors and bind one to the fixture IP."""
    deadline = time.monotonic() + timeout
    captured: list[dict] = []
    bound_change: dict | None = None
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(connect=5, read=5, write=5, pool=5), trust_env=False
    ) as client:
        async with client.stream("GET", url, headers={"Accept": "text/event-stream"}) as response:
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
    return captured, bound_change


def _validate_probe_result(result: dict, fixture_ip: str) -> None:
    """Fail unless every durable stage and the SSE cursor match the fixture."""
    binding = result["source_binding"]
    cursor_bound_to_fixture = (
        result["bound_ip_change"] is not None
        and result["bound_ip_change"]["ip"] == fixture_ip
    )
    if (
        result["checkpoint"] != result["expected_checkpoint"]
        or result["pg_observation_rows"] < 1
        or result["clickhouse_events"] < 1
        or not result["captured_sse_events"]
        or not cursor_bound_to_fixture
        or not binding["checkpoint_matches_fixture"]
        or not binding["observation_matches_fixture"]
    ):
        raise RuntimeError(json.dumps(result, sort_keys=True))


def _stop_probe_server(process: subprocess.Popen) -> None:
    """Stop the probe API process, force-killing it only after timeout."""
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


async def run_probe(args: argparse.Namespace) -> dict:
    """Exercise one synthetic event through durable storage, PG state, and SSE."""
    dsn = os.environ["POSTGRES_DSN"]
    source_id = f"e2e-probe-{uuid.uuid4().hex[:12]}"
    line, ip, final_offset = _fixture_log()
    released = asyncio.Event()
    connected = asyncio.Event()

    async def ws_handler(websocket):
        """Wait for the baseline, then deliver the deterministic fixture."""
        await _send_fixture(websocket, released, connected, line, final_offset)

    process = _start_probe_server(args, source_id)
    try:
        async with websockets.serve(ws_handler, "127.0.0.1", args.websocket_port):
            await wait_http(f"http://127.0.0.1:{args.http_port}/health")
            await asyncio.wait_for(connected.wait(), timeout=30)
            baseline = int(pg_value(dsn, "SELECT COALESCE(MAX(seq), 0) FROM ip_change_log"))
            released.set()
            captured, bound_change = await _capture_fixture_changes(
                dsn, f"http://127.0.0.1:{args.http_port}/api/stream", baseline, ip, args.timeout
            )

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
            _validate_probe_result(result, ip)
            print(json.dumps(result, indent=2, sort_keys=True))
            return result
    finally:
        released.set()
        _stop_probe_server(process)
        try:
            cleanup_ch(source_id)
            cleanup_pg(dsn, source_id, ip)
        except Exception as exc:
            print(f"cleanup warning: {type(exc).__name__}: {exc}", file=sys.stderr)


def main() -> int:
    """Parse probe options, validate prerequisites, and run the native check."""
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
