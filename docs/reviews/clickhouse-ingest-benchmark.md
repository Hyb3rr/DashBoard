# ClickHouse ingest benchmark

Date: 2026-09-18

## Scope

This is a native ClickHouse writer benchmark for the supported candidate batch
sizes. Each size was inserted three times through `app.db.clickhouse.insert_events`
against the local ClickHouse service, using a unique temporary dataset. The
temporary datasets were removed after the run.

The benchmark isolates ClickHouse insert cost. It does not claim to measure the
full collector path (PostgreSQL detection transaction, checkpoint acknowledgement,
raw archive latency, queue age, or end-to-end browser latency).

## Native results

| Batch | Runs (ms) | Median (ms) | Max observed (ms) | Median events/s |
|---:|---:|---:|---:|---:|
| 200 | 829.89, 90.47, 90.78 | 90.78 | 829.89 | 2,203.0 |
| 500 | 87.23, 93.57, 85.58 | 87.23 | 93.57 | 5,732.3 |
| 1000 | 94.37, 93.22, 99.20 | 94.37 | 99.20 | 10,596.8 |
| 2000 | 117.90, 105.17, 100.56 | 105.17 | 117.90 | 19,017.2 |

The first 200-row run includes connection establishment and is not treated as a
steady-state insert latency. The “max observed” column is the maximum of three
runs, not a statistically meaningful p95.

## Decision

The current default batch size remains **200**. The isolated insert benchmark is
not sufficient to change the collector default: larger batches improve raw
ClickHouse throughput but may increase PostgreSQL transaction time, queue age,
checkpoint latency, and end-to-end event latency. A full native WebSocket ingest
benchmark is required before changing the default.

The reusable writer is retained because it removes per-batch connection setup
without changing event identity, replay, checkpoint, or offset behavior.

## Verification limits

Native ClickHouse replay/idempotency verification passed separately. PostgreSQL
transaction latency, storage queue age, raw durability latency, CPU/RSS, and
full ingest-to-SSE latency were not measured by this isolated insert run.

## Read-path remeasurement

The current `traffic()` path (including its `http_events FINAL` queries and
PostgreSQL country lookup) was also measured three times per window against the
native local dataset:

| Window | Requests / unique IPs | Runs (ms) | Max observed (ms) |
|---:|---:|---:|---:|
| 1d | 825 / 112 | 609.64, 95.36, 90.11 | 609.64 |
| 7d | 6,373 / 616 | 299.51, 148.35, 159.94 | 299.51 |
| 30d | 24,568 / 1,688 | 220.19, 162.82, 121.30 | 220.19 |
| 90d | 24,568 / 1,688 | 132.60, 169.19, 174.61 | 174.61 |

At this current local scale there is no measured justification for adding a
ClickHouse aggregate read model or removing `FINAL`. Large-data load testing
remains an external/data-volume gate, not a reason to expand the schema now.

## Full collector path

The local native fixture was also run through WebSocket collector → raw archive
→ ClickHouse → PostgreSQL detection/state → checkpoint. Each run used a unique
source and fixture IP; ClickHouse and PostgreSQL fixture rows were removed after
verification.

| Batch | ClickHouse events | Checkpoint | Commit-to-checkpoint (ms) | Result |
|---:|---:|---:|---:|---|
| 200 | 200 / 200 | exact | 418.02 | PASS |
| 500 | 500 / 500 | exact | 825.43 | PASS |
| 1000 | 1000 / 1000 | exact | 1,446.11 | PASS |
| 2000 | 2000 / 2000 | exact | 2,264.17 | PASS |

This confirms durability and checkpoint correctness for the fixture, but does
not establish a universal production throughput limit. The current default of
200 remains the smallest tested batch and keeps commit latency below one second
in this local run; larger defaults are deferred until representative sustained
load data is available.
