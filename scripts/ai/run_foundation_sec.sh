#!/usr/bin/env bash
set -euo pipefail

: "${FOUNDATION_SEC_MODEL_PATH:?Set FOUNDATION_SEC_MODEL_PATH to local GGUF file}"
LLAMA_SERVER_BIN="${LLAMA_SERVER_BIN:-llama-server}"
LOCAL_REASONING_PORT="${LOCAL_REASONING_PORT:-8081}"
FOUNDATION_SEC_CONTEXT_SIZE="${FOUNDATION_SEC_CONTEXT_SIZE:-4096}"
FOUNDATION_SEC_GPU_LAYERS="${FOUNDATION_SEC_GPU_LAYERS:-0}"
PACKET_PATH="${1:?Usage: scripts/ai/run_foundation_sec.sh <case-packet.json>}"
ENDPOINT="${LOCAL_REASONING_BASE_URL:-http://127.0.0.1:${LOCAL_REASONING_PORT}/v1/chat/completions}"

server_pid=""
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

"$LLAMA_SERVER_BIN" --model "$FOUNDATION_SEC_MODEL_PATH" --host 127.0.0.1 \
  --port "$LOCAL_REASONING_PORT" --ctx-size "$FOUNDATION_SEC_CONTEXT_SIZE" \
  --parallel 1 --n-gpu-layers "$FOUNDATION_SEC_GPU_LAYERS" \
  --reasoning-format deepseek \
  >"${FOUNDATION_SEC_LOG_PATH:-/tmp/foundation-sec-llama-server.log}" 2>&1 &
server_pid=$!

for _ in $(seq 1 "${FOUNDATION_SEC_READY_ATTEMPTS:-60}"); do
  if curl --fail --silent "http://127.0.0.1:${LOCAL_REASONING_PORT}/health" >/dev/null 2>&1; then
    exec python3 -m scripts.ai.explain_case "$PACKET_PATH" --endpoint "$ENDPOINT" \
      --model "${FOUNDATION_SEC_MODEL_NAME:-Foundation-Sec-8B-Reasoning}" \
      --timeout "${LOCAL_REASONING_TIMEOUT_SECONDS:-30}"
  fi
  sleep 1
done

echo "llama-server did not become ready within bounded startup window" >&2
exit 1
