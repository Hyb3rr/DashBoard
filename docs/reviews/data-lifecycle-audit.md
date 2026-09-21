# Sentinel Hub Data Lifecycle Audit

Date: 2026-09-18
Scope: Phase 0 of Production Data-Lifecycle + Resource-Bounding Hardening

This audit is based on the current repository consumers and a native local
inventory of PostgreSQL and ClickHouse. It does not apply retention DDL or
delete production data.

## Native inventory

| Store/table | Current size | Observed time range | Primary owner |
|---|---:|---|---|
| ClickHouse `http_events` | 24,546 rows | 2026-08-20 → 2026-09-18 | Raw HTTP events and analytics |
| ClickHouse `behavior_events` | 2 rows | 2026-09-11 | Browser behavior evidence |
| PostgreSQL `ip_minute_features` | 14,063 rows | 2026-08-20 → 2026-09-18 | Detection/map minute aggregate |
| PostgreSQL `ip_minute_path_seen` | 21,129 rows | 2026-08-20 → 2026-09-18 | Detection path aggregate |
| PostgreSQL `processed_batches` | 5,794 rows | 2026-08-20 → 2026-09-18 | Replay/idempotency ledger |
| PostgreSQL `ip_change_log` | 50,000 rows | sequence-trimmed | Durable realtime cursor feed |
| PostgreSQL `alert_outbox` | 74 rows | 2026-08-22 → 2026-09-15 | Notification delivery state |
| PostgreSQL `ip_ai_scores` | 749 rows | scores from 2026-08-25 | Current AI score/read model |
| PostgreSQL `ai_explain_jobs` | 5,793 rows | 2026-09-04 → 2026-09-14 | Explanation job history |
| PostgreSQL `ai_trigger_deferred` | 76 rows | 2026-09-08 → 2026-09-10 | Deferred AI trigger work |
| PostgreSQL `country_demand_snapshot` | 31 snapshots | 2026-09-11 → 2026-09-18 | Published market read model |
| PostgreSQL `country_demand_signal` | 322 rows | follows snapshots | Snapshot child rows |
| PostgreSQL `industrial_demand_snapshot` | 7 snapshots | schema inventory only | Published market evidence |
| PostgreSQL `market_osm_snapshots` | 29 snapshots | 2026-08-25 → 2026-09-09 | Versioned OSM evidence |

## Lifecycle matrix

| Dataset | Consumers / maximum lookback | Replay or audit dependency | Safe to expire? | Minimum policy conclusion | Cleanup method |
|---|---|---|---|---|---|
| `http_events` | Traffic, map, historical investigation, Country Demand 7d/30d/90d plus previous comparable period | Raw evidence and replay source; ClickHouse `FINAL` protects dedupe semantics | Conditional | Do not use 30d. Current 90d comparison requires about 180d plus operational buffer; exact retention should be at least 210d until aggregation redesign is proven | ClickHouse TTL only after horizon and restore evidence are formalized |
| `behavior_events` | Behavior evidence and investigation | Raw supporting evidence; consumer horizon is not yet fully enumerated | Conditional | No TTL until behavior/session retention contract is documented | Separate timestamp-based ClickHouse TTL after audit |
| `ip_minute_features` | Detection windows up to 24h; map/traffic queries up to 30d; AI training 168h | Derived from raw events; recovery can rebuild only if raw horizon remains available | Conditional | Keep at least 30d plus buffer; proposed floor 37d pending query audit | Bounded PostgreSQL chunks by `bucket_minute` |
| `ip_minute_path_seen` | Detection path evidence, unique paths and AI feature frame; map/detection horizons | Derived state; path evidence supports investigation | Conditional | Same floor as minute features, at least 37d pending rare-path audit | Bounded PostgreSQL chunks by `bucket_minute` |
| `processed_batches` | Duplicate batch suppression and replay safety | Direct idempotency contract; source offsets do not prove old rows are no longer replayed | No, currently unresolved | Retain until a source/checkpoint replay-expiry proof exists | No deletion policy yet |
| `ip_change_log` | SSE wake-up cursor and `/api/ips/updates` durable delta | Cursor continuity; existing trim keeps latest 50,000 sequence rows | Yes, bounded | Keep existing sequence trim only; do not add timestamp cleanup | Existing bounded sequence trim |
| `alert_outbox` | Pending/retrying delivery and operational audit | Pending/retrying rows must never expire; delivered history can be separate | Conditional | Never delete pending/retrying; terminal delivered retention needs a separate policy | Bounded chunks by `delivered_at`, excluding active work |
| `ip_ai_scores` | Current IP detail and classification explanation | Current-state projection; older score is replaced, not historical source of truth | Yes, with care | Current rows are not a time series; no row retention needed. Evidence JSON has no independent cleanup contract | Keep current row; bound evidence per score |
| `ai_explain_jobs` | Job status, analyst audit and retry diagnosis | Job idempotency/fingerprint and explanation provenance | Conditional | Retain terminal history for an explicit audit period; never delete running/queued jobs | Bounded chunks by `completed_at`, excluding active states |
| `ai_trigger_deferred` | Deferred trigger consumer | Pending work must survive restart/retry | Conditional | Never delete pending rows; terminal/dead work requires explicit policy | Status-aware bounded cleanup after consumer audit |
| Country/market snapshots | Region/market read models and reproducibility | Published snapshot provenance and historical comparison | Yes, but not immediately | Retain published snapshots long enough for reproducibility; superseded/failed rows need explicit history policy | Snapshot-aware bounded cleanup, preserving published baseline |

## Important dependency findings

1. `CountryDemandService.refresh()` reads raw ClickHouse rows for both the
   current and previous period before aggregation. For the 90d mode this is a
   180d raw-data horizon. A 30d `http_events` TTL would silently change the
   product semantics and is prohibited.
2. `map_intelligence.py` reads PostgreSQL minute state for ranges up to 30d.
   Minute feature/path cleanup must preserve that horizon and include a buffer.
3. AI training uses a default 168-hour lookback, but its feature query also
   joins path evidence. The future resource-bounding phase must cap input
   explicitly rather than infer safety from the time window alone.
4. `processed_batches` is not ordinary history. It is part of the replay
   idempotency contract and remains unresolved for retention.
5. `ip_change_log` already has `_trim_change_log()` around the latest sequence
   range. A second retention mechanism would create competing cursor semantics.
6. Snapshot tables are intentionally versioned read models. Cleanup must keep
   a reproducible published snapshot and must not delete the only current
   source needed to explain a score.

## Phase 0 classification

### Safe to expire now

- None of the primary datasets are safe for an immediate destructive policy
  without a scheduler cleanup contract and native disposable-row test.
- `ip_change_log` is already bounded by its existing sequence trim; preserve
  that mechanism rather than adding another job.

### Expire only after derived state or policy exists

- `http_events` after the 180d Country Demand dependency is preserved.
- `ip_minute_features` and `ip_minute_path_seen` after a 30d-plus-buffer
  policy is tested against map/detection/AI consumers.
- Delivered `alert_outbox` rows after pending/retry semantics are excluded.
- Terminal AI jobs/deferred records after active-state retention is specified.
- Superseded market snapshots after reproducibility rules are explicit.

### Must remain / semantics unresolved

- `processed_batches`
- Pending or retrying `alert_outbox`
- Pending/running AI jobs and deferred triggers
- Raw `behavior_events` until its consumer horizon is inventoried
- The currently published snapshot required by each read model

## Phase 0 gate

No retention migration, destructive cleanup, or default horizon change is
justified by this audit alone. Phase 1 must define explicit configurable
policies and Phase 2 must implement bounded, isolated cleanup with replay/DR
regressions before any native data is removed.
