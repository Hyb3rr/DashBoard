#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT_DIR"

# The storage initializer runs before Python imports the application settings,
# so load project-local configuration explicitly for this launcher path.
if [[ -f "$ROOT_DIR/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT_DIR/.env"
  set +a
fi

POSTGRES_PORT="${POSTGRES_PORT:-55432}"
CLICKHOUSE_HTTP_PORT="${CLICKHOUSE_HTTP_PORT:-8123}"
POSTGRES_DATA_DIR="${POSTGRES_DATA_DIR:-$ROOT_DIR/data/postgres}"
CLICKHOUSE_DATA_DIR="${CLICKHOUSE_DATA_DIR:-$ROOT_DIR/data/clickhouse}"
CLICKHOUSE_BACKUP_TEMP_DIR="${CLICKHOUSE_BACKUP_TEMP_DIR:-$CLICKHOUSE_DATA_DIR/backups}"
CLICKHOUSE_TCP_PORT="${CLICKHOUSE_TCP_PORT:-9001}"
CLICKHOUSE_LOCK_DIR="${CLICKHOUSE_LOCK_DIR:-$ROOT_DIR/data/.clickhouse-launch.lock}"

mkdir -p "$ROOT_DIR/data"

if ! pg_isready -h 127.0.0.1 -p "$POSTGRES_PORT" >/dev/null 2>&1; then
  if [[ ! -f "$POSTGRES_DATA_DIR/PG_VERSION" ]]; then
    initdb -D "$POSTGRES_DATA_DIR" --auth=trust >/dev/null
  fi
  if ! pg_ctl -D "$POSTGRES_DATA_DIR" \
    -l "$ROOT_DIR/data/postgres.log" \
    -o "-p $POSTGRES_PORT" start >/dev/null; then
    if ! pg_isready -h 127.0.0.1 -p "$POSTGRES_PORT" >/dev/null 2>&1; then
      echo "PostgreSQL start failed and readiness check failed" >&2
      exit 1
    fi
  fi
fi

createdb -h 127.0.0.1 -p "$POSTGRES_PORT" ipintel 2>/dev/null || true

clickhouse_http_healthy() {
  curl -fsS "http://127.0.0.1:$CLICKHOUSE_HTTP_PORT/ping" >/dev/null 2>&1
}

clickhouse_tcp_ready() {
  nc -z -w 1 127.0.0.1 "$CLICKHOUSE_TCP_PORT" >/dev/null 2>&1
}

clickhouse_healthy() {
  clickhouse_http_healthy && clickhouse_tcp_ready
}

CLICKHOUSE_PID=""
CLICKHOUSE_LOCK_HELD="false"

if clickhouse_healthy; then
  echo "Reusing healthy ClickHouse on HTTP $CLICKHOUSE_HTTP_PORT / TCP $CLICKHOUSE_TCP_PORT"
else
  # Only one launcher may perform a ClickHouse startup. Re-check after taking
  # the lock because another launcher may have completed startup meanwhile.
  if ! mkdir "$CLICKHOUSE_LOCK_DIR" 2>/dev/null; then
    lock_pid=""
    for _ in {1..10}; do
      if [[ -f "$CLICKHOUSE_LOCK_DIR/pid" ]]; then
        lock_pid="$(<"$CLICKHOUSE_LOCK_DIR/pid")"
        break
      fi
      sleep 0.1
    done
    if [[ -n "$lock_pid" ]] && kill -0 "$lock_pid" 2>/dev/null; then
      echo "ClickHouse startup already managed by launcher PID $lock_pid" >&2
      exit 1
    fi
    if [[ -z "$lock_pid" ]]; then
      echo "ClickHouse startup lock exists without a readable owner; refusing to start another process" >&2
      exit 1
    fi
    rm -f "$CLICKHOUSE_LOCK_DIR/pid"
    rmdir "$CLICKHOUSE_LOCK_DIR" 2>/dev/null || {
      echo "ClickHouse startup lock is stale but could not be removed: $CLICKHOUSE_LOCK_DIR" >&2
      exit 1
    }
    mkdir "$CLICKHOUSE_LOCK_DIR"
  fi
  printf '%s\n' "$$" >"$CLICKHOUSE_LOCK_DIR/pid"
  CLICKHOUSE_LOCK_HELD="true"

  if clickhouse_healthy; then
    echo "ClickHouse became healthy while startup lock was acquired; reusing it"
    rm -f "$CLICKHOUSE_LOCK_DIR/pid"
    rmdir "$CLICKHOUSE_LOCK_DIR"
    CLICKHOUSE_LOCK_HELD="false"
  else
  mkdir -p "$CLICKHOUSE_DATA_DIR"
  mkdir -p "$CLICKHOUSE_BACKUP_TEMP_DIR"
  clickhouse server --config-file="$ROOT_DIR/infra/clickhouse/config.xml" -- \
    --path="$CLICKHOUSE_DATA_DIR" \
    --backups.allowed_path="$CLICKHOUSE_BACKUP_TEMP_DIR" \
    --http_port="$CLICKHOUSE_HTTP_PORT" \
    --tcp_port="$CLICKHOUSE_TCP_PORT" \
    >"$ROOT_DIR/data/clickhouse.log" 2>&1 &
  CLICKHOUSE_PID=$!

  for _ in {1..30}; do
    if clickhouse_healthy; then
      break
    fi
    if ! kill -0 "$CLICKHOUSE_PID" 2>/dev/null; then
      echo "ClickHouse exited during startup; inspect data/clickhouse.log" >&2
      exit 1
    fi
    sleep 1
  done
  if ! clickhouse_healthy; then
    echo "ClickHouse did not become healthy on HTTP $CLICKHOUSE_HTTP_PORT and TCP $CLICKHOUSE_TCP_PORT within 30 seconds" >&2
    exit 1
  fi
  fi
fi

# Apply the tracked PostgreSQL/ClickHouse migrations after both databases are
# ready and before starting the app. Keeping DDL out of FastAPI's live
# lifespan avoids migration lock work on the realtime request path.
.venv/bin/python scripts/ops/init_storage.py

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

LLAMA_SERVER_PID=""
AI_EXPLAIN_WORKER_PID=""
AI_TRIGGER_PID=""
UVICORN_PID=""
DATA_SCHEDULER_PID=""

start_local_ai() {
  if [[ "${AI_EXPLAIN_WORKER_ENABLED:-true}" != "true" ]]; then
    echo "Local AI explain worker disabled by configuration"
    return
  fi
  if [[ -z "${FOUNDATION_SEC_MODEL_PATH:-}" || ! -f "${FOUNDATION_SEC_MODEL_PATH}" ]]; then
    echo "Local AI explain worker unavailable: FOUNDATION_SEC_MODEL_PATH is not configured" >&2
    return
  fi
  if ! command -v "${LLAMA_SERVER_BIN:-llama-server}" >/dev/null 2>&1; then
    echo "Local AI explain worker unavailable: llama-server was not found" >&2
    return
  fi

  "${LLAMA_SERVER_BIN:-llama-server}" --model "$FOUNDATION_SEC_MODEL_PATH" \
    --host 127.0.0.1 --port "${LOCAL_REASONING_PORT:-8081}" \
    --ctx-size "${FOUNDATION_SEC_CONTEXT_SIZE:-4096}" --parallel 1 \
    --n-gpu-layers "${FOUNDATION_SEC_GPU_LAYERS:-0}" \
    --threads "${FOUNDATION_SEC_THREADS:-6}" \
    --reasoning-format deepseek \
    >"${FOUNDATION_SEC_LOG_PATH:-$ROOT_DIR/data/foundation-sec-llama-server.log}" 2>&1 &
  LLAMA_SERVER_PID=$!

  for _ in $(seq 1 "${FOUNDATION_SEC_READY_ATTEMPTS:-60}"); do
    if curl --fail --silent "http://127.0.0.1:${LOCAL_REASONING_PORT:-8081}/health" >/dev/null 2>&1; then
      "${ROOT_DIR}/.venv/bin/python" -m scripts.ai.run_explain_worker \
        --packets "${AI_EXPLAIN_PACKETS_PATH:-$ROOT_DIR/data/ai/corpora/foundation-sec-real.json}" \
        >"$ROOT_DIR/data/ai-explain-worker.log" 2>&1 &
      AI_EXPLAIN_WORKER_PID=$!
      "${ROOT_DIR}/.venv/bin/python" -m scripts.ai.run_ai_trigger --enabled \
        >"$ROOT_DIR/data/ai-trigger.log" 2>&1 &
      AI_TRIGGER_PID=$!
      echo "Local AI explain worker ready on 127.0.0.1:${LOCAL_REASONING_PORT:-8081}"
      return
    fi
    if ! kill -0 "$LLAMA_SERVER_PID" 2>/dev/null; then
      echo "Local AI model server exited during startup; inspect ${FOUNDATION_SEC_LOG_PATH:-$ROOT_DIR/data/foundation-sec-llama-server.log}" >&2
      LLAMA_SERVER_PID=""
      return
    fi
    sleep 1
  done
  echo "Local AI model server did not become ready within bounded startup window" >&2
  kill "$LLAMA_SERVER_PID" 2>/dev/null || true
  wait "$LLAMA_SERVER_PID" 2>/dev/null || true
  LLAMA_SERVER_PID=""
}

start_data_scheduler() {
  if [[ "${DATA_SCHEDULER_ENABLED:-false}" != "true" ]]; then
    echo "Data refresh scheduler disabled by configuration"
    return
  fi
  (
    while true; do
      "${ROOT_DIR}/.venv/bin/python" -m scripts.ops.data_scheduler \
        >>"$ROOT_DIR/data/data-scheduler.log" 2>&1 || true
      sleep "${DATA_SCHEDULER_INTERVAL_SECONDS:-3600}"
    done
  ) &
  DATA_SCHEDULER_PID=$!
  echo "Data refresh scheduler started (interval ${DATA_SCHEDULER_INTERVAL_SECONDS:-3600}s)"
}

cleanup() {
  if [[ -n "$CLICKHOUSE_PID" ]] && kill -0 "$CLICKHOUSE_PID" 2>/dev/null; then
    kill "$CLICKHOUSE_PID" 2>/dev/null || true
  fi
  if [[ -n "$AI_EXPLAIN_WORKER_PID" ]] && kill -0 "$AI_EXPLAIN_WORKER_PID" 2>/dev/null; then
    kill "$AI_EXPLAIN_WORKER_PID" 2>/dev/null || true
    wait "$AI_EXPLAIN_WORKER_PID" 2>/dev/null || true
  fi
  if [[ -n "$AI_TRIGGER_PID" ]] && kill -0 "$AI_TRIGGER_PID" 2>/dev/null; then
    kill "$AI_TRIGGER_PID" 2>/dev/null || true
    wait "$AI_TRIGGER_PID" 2>/dev/null || true
  fi
  if [[ -n "$LLAMA_SERVER_PID" ]] && kill -0 "$LLAMA_SERVER_PID" 2>/dev/null; then
    kill "$LLAMA_SERVER_PID" 2>/dev/null || true
    wait "$LLAMA_SERVER_PID" 2>/dev/null || true
  fi
  if [[ -n "$UVICORN_PID" ]] && kill -0 "$UVICORN_PID" 2>/dev/null; then
    kill "$UVICORN_PID" 2>/dev/null || true
    wait "$UVICORN_PID" 2>/dev/null || true
  fi
  if [[ -n "$DATA_SCHEDULER_PID" ]] && kill -0 "$DATA_SCHEDULER_PID" 2>/dev/null; then
    kill "$DATA_SCHEDULER_PID" 2>/dev/null || true
    wait "$DATA_SCHEDULER_PID" 2>/dev/null || true
  fi
  if [[ "$CLICKHOUSE_LOCK_HELD" == "true" ]]; then
    rm -f "$CLICKHOUSE_LOCK_DIR/pid"
    rmdir "$CLICKHOUSE_LOCK_DIR" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

start_local_ai
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 &
UVICORN_PID=$!
start_data_scheduler
wait "$UVICORN_PID"
