#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT_DIR"

POSTGRES_PORT="${POSTGRES_PORT:-55432}"
CLICKHOUSE_HTTP_PORT="${CLICKHOUSE_HTTP_PORT:-8123}"
POSTGRES_DATA_DIR="${POSTGRES_DATA_DIR:-$ROOT_DIR/data/postgres}"
CLICKHOUSE_DATA_DIR="${CLICKHOUSE_DATA_DIR:-$ROOT_DIR/data/clickhouse}"

mkdir -p "$ROOT_DIR/data"

if ! pg_isready -h 127.0.0.1 -p "$POSTGRES_PORT" >/dev/null 2>&1; then
  if [[ ! -f "$POSTGRES_DATA_DIR/PG_VERSION" ]]; then
    initdb -D "$POSTGRES_DATA_DIR" --auth=trust >/dev/null
  fi
  pg_ctl -D "$POSTGRES_DATA_DIR" \
    -l "$ROOT_DIR/data/postgres.log" \
    -o "-p $POSTGRES_PORT" start >/dev/null
fi

createdb -h 127.0.0.1 -p "$POSTGRES_PORT" ipintel 2>/dev/null || true

# Refresh local SAPICS MMDBs before app start. Failed network/update keeps
# last-known-good files and must not prevent local development startup.
if [[ "${SAPICS_UPDATE_ON_STARTUP:-true}" == "true" ]]; then
  SAPICS_DATA_DIR="${SAPICS_DATA_DIR:-$ROOT_DIR/data/ip_location}" \
    .venv/bin/python -c 'from app.services.sapics_updater import refresh; print(refresh())' >>"$ROOT_DIR/data/sapics-updater.log" 2>&1 \
    || echo "SAPICS update failed; keeping last-known-good data" >&2
fi
if [[ "${IP2REGION_UPDATE_ON_STARTUP:-true}" == "true" ]]; then
  IP2REGION_DATA_DIR="${IP2REGION_DATA_DIR:-$ROOT_DIR/data/ip2region}" \
    .venv/bin/python -c 'from app.services.ip2region_updater import refresh; print(refresh())' >>"$ROOT_DIR/data/ip2region-updater.log" 2>&1 \
    || echo "ip2region update failed; keeping last-known-good data" >&2
fi

CLICKHOUSE_PID=""
if ! curl -fsS "http://127.0.0.1:$CLICKHOUSE_HTTP_PORT/ping" >/dev/null 2>&1; then
  mkdir -p "$CLICKHOUSE_DATA_DIR"
  clickhouse server -- \
    --path="$CLICKHOUSE_DATA_DIR" \
    --http_port="$CLICKHOUSE_HTTP_PORT" \
    --tcp_port=9001 \
    >"$ROOT_DIR/data/clickhouse.log" 2>&1 &
  CLICKHOUSE_PID=$!

  for _ in {1..30}; do
    curl -fsS "http://127.0.0.1:$CLICKHOUSE_HTTP_PORT/ping" >/dev/null 2>&1 && break
    sleep 1
  done
  curl -fsS "http://127.0.0.1:$CLICKHOUSE_HTTP_PORT/ping" >/dev/null
fi

cleanup() {
  if [[ -n "$CLICKHOUSE_PID" ]] && kill -0 "$CLICKHOUSE_PID" 2>/dev/null; then
    kill "$CLICKHOUSE_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

exec .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
