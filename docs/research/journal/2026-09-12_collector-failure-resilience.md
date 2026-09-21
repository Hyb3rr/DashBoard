# Collector Failure Resilience Journal

## 2026-09-12 — Phase 0

### Scope

Failure-resilience work for `WebSocketCollector` and `RawLogArchive`.

### Locked invariants

- Durable PostgreSQL checkpoint is the replay cursor.
- Lease loss must not become operator shutdown.
- Uncommitted in-memory work is replayable only after returning to the durable
  cursor.
- Offset arithmetic remains unchanged until the upstream protocol is verified.

### Initial findings

- `run()` performs initial checkpoint/lease operations before the WebSocket
  connection exception boundary.
- `start()` treats an existing completed task as already started.
- Storage checkpoint fencing currently sets global `_stop`.
- Storage worker termination can leave queue work unfinished.
- Raw archive write retry is unbounded and has no backoff/terminal state.
- Collector liveness is not part of overall health.
- Three WebSocket collector integration tests are skip stubs.

### Phase status

- Phase 0: complete. Focused baseline ran; DB-dependent tests can hang/fail
  when PostgreSQL at the configured port is unavailable. This remains an
  environment gate, not a collector code result.

## 2026-09-12 — Phase 1 / Patch A

### Changes

- `WebSocketCollector.start()` now distinguishes an alive task from a stale
  completed task and clears the stale reference before starting again.
- `run()` is supervised by `_supervise_run()` with bounded exponential retry
  backoff and explicit task-failure/restart metrics.
- Collector status persistence failures are contained and reported as control-
  plane failures instead of escaping from status publication.
- Offset arithmetic and lease-loss semantics were intentionally unchanged.

### Evidence

- Added `tests/test_collector_resilience.py`.
- Patch A targeted suite: 12 passed.
- No PostgreSQL integration was claimed.

### Phase status

- Phase 1: complete.
- Phase 2: complete.

## 2026-09-12 — Phase 2 / Patch B

### Changes

- `CheckpointRepository.renew()` now returns whether the lease row was
  actually renewed for the current owner.
- Lease renewal exceptions or ownership loss signal `_lease_lost`; they do
  not set global `_stop`.
- The active WebSocket is closed when lease ownership is lost so the current
  connection cycle can terminate promptly.
- Checkpoint fencing rejection follows the same lease-loss path.
- Uncommitted storage queue work and pending in-memory lines are drained as
  replayable work, then the durable PostgreSQL offset is reloaded before the
  next cycle.

### Evidence

- Added deterministic tests for lease-loss signaling and durable-offset reset.
- Patch B targeted suite: 14 passed.
- Offset arithmetic was not changed.
- No PostgreSQL integration was claimed.

### Phase status

- Phase 2: complete.
- Phase 3: pending review; next scope is upstream offset-contract evidence.

## 2026-09-12 — Phase 3

Offset arithmetic remains frozen while the upstream framing contract is
audited. Evidence is being collected from the repository protocol client,
fixtures and tests; no server-side protocol specification is present yet.

### Phase status

- Phase 3 is blocked on authoritative upstream answers for cursor unit,
  encoding/newline semantics, frame ordering, and replay behavior.
- No offset arithmetic was changed and no speculative checkpoint behavior was
  introduced.

## 2026-09-12 — Phases 4–7

### Phase 4 — bounded raw-archive failure policy

- Added bounded write attempts with cancellable exponential backoff.
- Added explicit `READY`, `RETRYING`, and `FAILED` writer state and metrics.
- Terminal write failure fails the in-flight and queued receipts, drains queue
  accounting, and prevents detection/storage acknowledgement through the
  existing durability barrier.
- `append_batch()` and `tap()` reject new work while the writer is failed.

### Phase 5 — chunk-rotation durability

- Sealing now fsyncs the active payload before rename, fsyncs temporary sealed
  metadata before publication, and fsyncs the containing directory after
  rename/publication.
- Existing receipt and chunk semantics were preserved.

### Phase 6 — liveness visibility

- Collector status now exposes task liveness for run/flush/storage/enrichment/
  privacy and raw writer state.
- `/health` degrades when an enabled collector has failed/stopped/cancelled
  worker tasks or a terminal raw-writer failure; disabled/config-error mode is
  not treated as an ingestion failure.

### Phase 7 — validation

- Focused resilience/raw-archive/WebSocket suite: `31 passed, 1 skipped`.
- Follow-up raw archive + resilience suite: `23 passed, 1 skipped`.
- `python -m compileall -q app scripts tests`: passed.
- `git diff --check`: passed.
- The remaining skip is environment/integration-related; no database
  integration pass is claimed.

### Workstream status

- Phases 1, 2, and 4–7 complete for available deterministic coverage.
- Phase 3 remains blocked pending authoritative upstream offset protocol
  specification. PostgreSQL/ClickHouse integration remain environment gates.

## 2026-09-12 — Review follow-up

### Phase 2 closure

- Fixed the lease-loss liveness gap where `_storage_loop()` could terminate on
  `CheckpointCommitRejected` while `_storage_task` remained a completed,
  truthy reference.
- Storage enqueue now recreates a completed worker before accepting the next
  batch; shutdown drains rather than waiting on a dead worker.
- Renewal now requires an unexpired lease, so an expired owner must reacquire
  instead of resurrecting its old lease.
- Added a deterministic regression covering rejection, worker termination,
  worker recreation and successful processing of the next batch.

### Phase 4 closure

- Terminal raw-writer failure now clears failed receipt-group metadata and does
  not touch collector-owned queue-age state.
- A later append probes/restarts the archive writer, allowing recovery without
  an application restart when the underlying storage becomes writable again.
- Added a recovery regression; focused collector/archive tests pass.
- Restarting a failed writer now preserves live compression/upload tasks and
  only creates maintenance workers when the previous task is absent or done.
- Added a regression preventing duplicate maintenance workers during writer
  recovery.

### Final validation

- Broad non-integration suite reached 100% with no failures; environment-backed
  skips remain classified as integration gates.
- `python -m compileall -q app scripts tests`: passed.
- `git diff --check`: passed.
- Local web health probe to `127.0.0.1:8000` could not connect because no
  service was running; browser/live-dashboard verification was not claimed.

## 2026-09-12 — ClickHouse migration execution follow-up

- Added an ordered ClickHouse migration runner with a schema-migration ledger
  and checksum validation.
- `scripts/ops/init_storage.py` now applies tracked ClickHouse migrations before
  calling the verify-only runtime contract.
- Added migration `006_behavior_events_geo_confidence_float64.sql` to upgrade
  existing `Nullable(Float32)` behavior-event columns without rewriting the
  deployed `005` migration.
- Runner/schema tests: `16 passed`.
- Applying the migration to the local server remains blocked because the local
  ClickHouse service is unavailable; `dev_run.sh` is also currently blocked by
  local PostgreSQL readiness.

## 2026-09-12 — ClickHouse ledger checksum follow-up

- Read-only comparison classified the likely failure as driver
  bytes-vs-string normalization (`FixedString(64)`), not evidence of changed
  migration contents. The live ledger could not be inspected because
  ClickHouse was unreachable.
- The runner now decodes driver-returned bytes for both filename and checksum;
  genuine checksum changes remain fail-closed.
- Added regressions for accepting an already-applied bytes-valued checksum and
  rejecting a genuinely different checksum.
- Migration/schema tests: `19 passed`; compileall and diff check passed.

## 2026-09-12 — Complete ClickHouse schema-drift audit

- Real `system.columns` audit found eight confirmed legacy mismatches in
  `behavior_events`: `cf_js_detection_passed`, `geo_conflict`, `is_hosting`,
  `is_mobile`, `is_proxy`, `is_scanner`, `is_tor`, and `is_vpn` were
  `Nullable(Bool)` instead of the strict runtime `Nullable(UInt8)` contract.
- Existing values were checked before repair; all eight columns contained only
  `NULL`, so the Bool-to-UInt8 conversion was data-preserving for this local
  database.
- Added one forward migration, `007_normalize_evidence_column_types.sql`,
  without editing migrations 001–006.
- Applied migration 007 to the real local ClickHouse. Ledger now contains
  versions 001..007 and `verify_schema()` passes; repaired columns all report
  `Nullable(UInt8)` and `geo_confidence` reports `Nullable(Float64)`.
- `dev_run.sh` reached `Storage schema and market catalog ready`; it then
  blocked in the network-dependent SAPICS updater and was stopped. No web
  server readiness was claimed.
- Broad non-integration suite: passed 100%; compileall and diff check passed.
