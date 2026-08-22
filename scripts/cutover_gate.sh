#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT_DIR"
PYTHON="${PYTHON:-.venv/bin/python}"
PYTEST="${PYTEST:-.venv/bin/pytest}"
TIMEOUT="${TEST_TIMEOUT_SECONDS:-90}"

if [[ -z "${POSTGRES_DSN:-}" || -z "${CLICKHOUSE_HOST:-}" ]]; then
  echo 'CUTOVER GATE: FAIL'
  echo 'POSTGRES_DSN and CLICKHOUSE_HOST are required; integration tests must not be skipped.'
  exit 2
fi

run_tests() {
  "$PYTHON" scripts/run_pytest.py --timeout "$TIMEOUT" -- "$PYTEST" "$@"
}

echo '[1/7] compile'
"$PYTHON" -m compileall -q app
git diff --check

echo '[2/7] unit/non-parity suite'
run_tests -m 'not parity and not failure and not soak and not integration' --durations=20

echo '[3/7] deterministic parity'
run_tests -m parity --durations=20

echo '[4/7] failure/replay'
run_tests -m failure --durations=20

echo '[5/7] outage simulation'
run_tests -m outage --durations=20

echo '[6/7] split HTTP smoke'
DATA_BACKEND=split run_tests -m smoke --durations=20

echo '[7/7] gate result'
echo 'CUTOVER GATE: PASS'
