## Project

Build a **read-only Remote Web Monitoring Hub** for WordPress/web servers.

The monitored server only exposes logs.

This project must **never modify, block, configure, restart, remediate, or execute commands on the monitored remote server**.

The primary product responsibility is:

> Show live security telemetry with low latency, reliable ingestion, replay safety, and clear investigation evidence.

Realtime performance and reliability are more important than feature count.

---

## Current Architecture

```text
Remote Web Server
      ↓ logs
WebSocket Collector
      ↓
Normalizer
      ↓
 ┌───────────────────────┬────────────────────────┐
 │                       │                        │
 ▼                       ▼                        ▼
ClickHouse           PostgreSQL              Detection
Raw events           Mutable state           Rules
Time-series          IP profiles             Risk scoring
Traffic analytics    Intel metadata          Isolation Forest
Historical events    Checkpoints             Classification
                     Leases
                     Alerts
                     Change feed
                     AI state
      │                       │
      └──────────────┬────────┘
                     ↓
                  FastAPI
                     ↓
              SSE / REST APIs
                     ↓
                 Dashboard
````

---

## Data Ownership

### ClickHouse

ClickHouse owns:

- raw live HTTP events
    
- traffic/time-series data
    
- historical event queries
    
- request/path analytics
    
- event aggregation
    
- high-volume analytical queries
    

Raw events must remain available for investigation.

Do not move mutable application state into ClickHouse without a measured reason.

### PostgreSQL

PostgreSQL owns:

- IP profiles
    
- classification state
    
- risk/detection state
    
- intelligence metadata
    
- provider refresh state
    
- privacy/threat metadata
    
- collector checkpoints
    
- leases
    
- idempotency state
    
- alert/outbox state
    
- change feed
    
- AI model state
    
- analyst/application state
    
- region/intelligence state
    

### SQLite

SQLite is **not part of the architecture**.

Do not:

- add SQLite dependencies
    
- create `.db` or `.sqlite` files
    
- add SQLite fallbacks
    
- reintroduce file/offline analysis mode
    
- add compatibility paths for legacy SQLite behavior
    

If obsolete SQLite code is discovered, remove it through the normal approval process.

---

## Main Stack

- Python
    
- FastAPI
    
- PostgreSQL
    
- ClickHouse
    
- HTML / CSS / JavaScript dashboard
    
- SSE for realtime dashboard updates
    
- WebSocket collector for remote log ingestion
    
- Rule-based detection
    
- Isolation Forest anomaly detection
    

Do not introduce React, Next.js, Redis, Kafka, or additional infrastructure unless a measured problem requires it.

---

## Main Responsibilities

### Collector

Responsible for:

- receiving remote logs
    
- reconnecting safely
    
- heartbeat/status
    
- batching
    
- deterministic event identity
    
- replay-safe ingestion
    
- source-offset checkpointing
    

The collector must not lose or duplicate events during reconnect/replay.

### Normalization

Responsible for:

- parsing supported web-server log formats
    
- producing deterministic normalized event fields
    
- preserving raw evidence
    
- keeping normalization inexpensive
    

### Detection

Responsible for:

- deterministic security rules
    
- rolling behavioral signals
    
- risk scoring
    
- classification
    
- anomaly detection
    
- evidence generation
    

Detection semantics must remain explainable and testable.

### Enrichment

Responsible for:

- GeoIP
    
- ASN/network identity
    
- Tor/VPN/proxy/hosting signals
    
- reputation/intelligence
    
- provider freshness
    
- disagreement/confidence metadata
    

Never perform expensive remote enrichment synchronously inside request handlers or per-event ingestion.

### AI

Current AI detection may use Isolation Forest.

Future local LLM functionality should primarily act as a **Case Explainer**, not as the authoritative BAD/WATCH classifier.

Preferred flow:

```text
Rules / Isolation Forest / deterministic scoring
                 ↓
          classification/evidence
                 ↓
             Local LLM
                 ↓
      grounded human-readable explanation
```

AI explanation must reference existing evidence and must not invent evidence.

### API

FastAPI routes should orchestrate only.

Business logic belongs in services.

Database-specific logic belongs in repositories/storage modules.

### Dashboard

Dashboard priorities:

1. live telemetry
    
2. fast investigation
    
3. clear evidence
    
4. low data-transfer cost
    
5. minimal unnecessary rerendering
    
6. no blocking/remediation controls
    

---

## Core Product Invariants

1. The dashboard is read-only toward monitored servers.
    
2. ClickHouse stores raw/live event and time-series data.
    
3. PostgreSQL stores mutable application/state/intelligence data.
    
4. SQLite must not exist in runtime architecture.
    
5. Raw logs must remain available for investigation.
    
6. Source offsets advance only after successful processing.
    
7. Replay must be idempotent.
    
8. Duplicate batches must not create duplicate counters/events.
    
9. Rules must remain deterministic, versioned, and testable.
    
10. Risk decisions must expose supporting evidence.
    
11. Geo/network intelligence should expose confidence/disagreement where relevant.
    
12. Expensive remote calls must not execute synchronously on the ingest/request hot path.
    
13. Realtime UI updates should use event/delta semantics rather than unnecessary full reloads.
    
14. No active blocking, firewall actions, SSH control, or automatic remediation.
    
15. Do not expose API keys, tokens, cookies, credentials, or secrets in logs or commits.
    

---

## Performance Rules

Before changing code, identify whether the code runs:

- per event
    
- per batch
    
- per request
    
- per IP
    
- periodically
    
- on-demand only
    

For per-event and per-request paths, do not add:

- remote network calls
    
- synchronous enrichment
    
- repeated database connections inside loops
    
- historical full-table scans
    
- large ClickHouse queries
    
- full snapshot rebuilds
    
- synchronous AI/LLM inference
    
- unnecessary full dashboard refreshes
    

Prefer:

- batched writes
    
- periodic aggregation
    
- bounded queries
    
- asynchronous background work
    
- reusable database pools
    
- deterministic incremental processing
    

For high-volume analytics, prefer ClickHouse.

For mutable transactional state, prefer PostgreSQL.

Do not optimize architecture preemptively.

Measure first.

---

## Rare / Statistical Detection Rules

Statistical detectors such as rare-path detection must not run expensive historical queries for every incoming event.

Preferred design:

```text
ClickHouse events
      ↓
periodic batch analysis
      ↓
statistical evidence
      ↓
PostgreSQL state/evidence
      ↓
Dashboard
```

A rare signal is supporting evidence, not proof of malicious behavior.

For example:

```text
rare path != malicious path
```

Rare-path detection should consider:

- canonicalized path
    
- distinct source-IP population
    
- historical frequency
    
- temporal frequency
    
- first-seen/newness
    
- rare-path burst behavior
    

Dynamic path components must be normalized carefully.

Do not blindly lowercase URL paths.

---

## Evidence Model

New detectors should prefer producing a common structured evidence format.

Evidence should contain, where applicable:

- evidence ID
    
- detector/rule source
    
- observed value
    
- threshold/baseline
    
- score contribution
    
- timestamp
    
- explanation
    
- supporting context
    
- freshness
    

Examples:

```text
rule evidence
behavior evidence
rarity evidence
privacy/reputation evidence
AI anomaly evidence
geo/network context
```

Evidence should be reusable by:

- IP Detail
    
- Evidence Panel
    
- What Changed
    
- alerts
    
- future local AI explanation
    

Do not create separate incompatible evidence formats for every feature.

---

## IP Detail Direction

The IP investigation view should prioritize:

```text
Summary
- IP
- Classification
- Risk
- Confidence
- Country
- ASN
- Network type
- Requests
- Last seen

Evidence Panel
- rule evidence
- observed vs threshold
- score contribution
- behavioral evidence
- rarity evidence
- privacy/reputation evidence
- anomaly evidence

Data Freshness
- relative time only
- color changes with age
- source-specific freshness thresholds
```

Do not create a separate Rule Explain panel if the information belongs in Evidence Panel.

Do not implement progressive/lazy API splitting until measurements show the current IP-detail query is a real performance problem.

---

## What Changed

`What Changed` belongs on the main dashboard.

It should show semantic changes only, for example:

- UNKNOWN → WATCH
    
- WATCH → BAD
    
- new significant rule
    
- new rare endpoint
    
- rare-path burst
    
- meaningful risk change
    
- material geo/privacy change
    
- AI anomaly state change
    

Do not emit noisy technical updates such as every database write or `updated_at` change.

Clicking an IP should lead to IP Detail and its evidence.

---

## Change Approval Policy

Before making ANY change that:

- edits files
    
- creates files
    
- moves files
    
- deletes files
    
- installs/removes dependencies
    
- changes database schema
    
- changes environment/configuration
    
- restarts services
    
- changes runtime behavior
    
- materially affects the system
    

STOP and ask for approval first.

Before asking, provide:

1. Plain-language understanding of the goal.
    
2. Root cause or architectural reason.
    
3. Exact implementation approach.
    
4. Exact files to modify.
    
5. Expected effect on realtime performance, latency, and reliability.
    
6. Validation plan.
    

Wait for explicit `go` before modifying anything.

Read-only inspection does not require approval.

Allowed read-only actions include:

- reading/searching source
    
- inspecting Git
    
- inspecting config/schema
    
- reading logs
    
- querying health/status
    
- running existing tests
    
- running Playwright
    
- inspecting processes/ports
    
- measuring existing performance
    

---

## File Scope Rule

Before modifying files, list every file intended for modification.

README and test files count.

If more than **5 files** would be modified in one phase:

STOP and split the work into smaller independently testable phases.

Do not silently modify files that were not listed.

---

## Root-Cause Policy

Never introduce:

- temporary hacks
    
- unnecessary fallbacks
    
- duplicated implementations
    
- compatibility shims
    
- band-aid fixes
    

when the root cause can be corrected cleanly.

Prefer deleting obsolete complexity over preserving unused compatibility.

If a failing test checks obsolete implementation details, update the test to verify the current behavioral contract.

Do not alter production architecture merely to satisfy a stale test.

---

## Realtime Safety

Any change affecting ingestion must preserve:

```text
event received
      ↓
ClickHouse durable event write
      ↓
PostgreSQL state/detection processing
      ↓
successful commit
      ↓
source offset acknowledgement
```

The exact internal ordering may differ where designed, but these invariants must hold:

- no acknowledged event is lost
    
- replay is safe
    
- duplicate batch replay is idempotent
    
- counters do not double count
    
- source offset does not advance on failed processing
    

---

## Validation

After every approved code phase:

1. Run relevant unit/backend tests.
    
2. Run integration tests where infrastructure is available.
    
3. Run Playwright against the actual dashboard.
    
4. Verify the existing live dashboard still behaves correctly.
    

Playwright should verify, where applicable:

- dashboard loads
    
- realtime connection works
    
- incoming event appears without refresh
    
- counters update
    
- charts update
    
- IP list updates
    
- IP Detail loads
    
- filters work
    
- sorting works
    
- region/intelligence views work
    
- health/collector status works
    
- no console errors
    
- no unexpected 4xx/5xx
    

For realtime-ingestion changes additionally verify:

- reconnect
    
- replay
    
- no lost events
    
- no duplicate events
    
- no duplicate counters
    
- acceptable latency
    

Do not weaken Playwright assertions merely to make a refactor pass.

Tests are behavioral contracts.

If a test is stale because of an intentional architecture change, explain the reason before updating it.

---

## Performance Validation

For hot-path changes, compare before/after behavior using existing telemetry or reproducible tests.

Useful metrics include:

- ingest batch duration
    
- ClickHouse insert latency
    
- PostgreSQL query latency
    
- rule evaluation latency
    
- dashboard event lag
    
- lost events
    
- duplicate events
    
- queue depth
    
- reconnect count
    

Prefer p50/p95/p99 where practical rather than relying only on averages.

If a change introduces missing/duplicate events, stop.

If latency materially regresses, investigate before proceeding.

---

## Failure Policy

After three consecutive failed attempts on the same problem:

STOP.

Do not make a fourth patch.

Report:

1. safest revert point
    
2. confirmed facts
    
3. unknowns
    
4. likely root cause
    
5. materially different next approach
    

---

## Documentation

Update README after:

- an architectural phase
    
- a user-visible feature
    
- a major storage/data-flow change
    

Do not create README churn for tiny internal fixes.

README should reflect current architecture only.

Do not document SQLite/file mode as part of the active architecture.

---

## Skill Selection Rule

Before starting a non-trivial coding task, automatically choose the most relevant skill or skills.

Do not ask the user which skill to use.

Use one primary skill by default.

Add at most one supporting skill when it materially improves the task.

Do not use more than two skills for one phase unless you explain why first.

Repository-specific rules in this file always override generic skill advice.

Do not force a skill onto trivial typo-only, docs-only, or tiny isolated changes.

### Designing Data-Intensive Applications

Use as primary for:

- PostgreSQL architecture
    
- ClickHouse architecture
    
- batching
    
- aggregation
    
- replay/idempotency
    
- consistency
    
- queues
    
- throughput
    
- latency
    
- retention
    
- realtime data flow
    
- statistical detector data pipelines
    

Typical use:

```text
Rare Path Detector
ClickHouse analytics
high-volume event processing
```

Recommended supporting skill:

```text
Refactoring
```

### Refactoring

Use for:

- restructuring existing code
    
- extracting modules
    
- reducing duplication
    
- simplifying code
    
- preserving behavior during cleanup
    
- improving maintainability
    

Typical use:

```text
main.py cleanup
frontend module extraction
repository/service cleanup
```

Recommended supporting skill:

```text
Clean Architecture
```

### Clean Architecture

Use for:

- service boundaries
    
- repository boundaries
    
- FastAPI router organization
    
- dependency direction
    
- separating business logic from transport/storage
    
- designing new application modules
    
- Evidence model design
    

Typical use:

```text
IP Detail
Evidence Panel
Data Freshness
What Changed
```

Recommended supporting skill:

```text
Refactoring
```

### Working Effectively with Legacy Code

Use for:

- risky legacy cleanup
    
- obsolete compatibility removal
    
- persistence migration
    
- changing weakly tested legacy behavior
    

Recommended supporting skill:

```text
Refactoring
```

### Release It!

Use for:

- outages
    
- retries
    
- reconnects
    
- backpressure
    
- health checks
    
- resource exhaustion
    
- pool failures
    
- failure recovery
    
- production reliability
    

Typical use:

```text
PostgreSQL outage handling
ClickHouse outage handling
collector reconnect/recovery
```

Recommended supporting skill:

```text
Designing Data-Intensive Applications
```

### Recommended Project Mapping

```text
Rare Path Detector / ClickHouse analytics
→ Primary: Designing Data-Intensive Applications
→ Supporting: Refactoring

IP Detail / Evidence Panel / Data Freshness / What Changed
→ Primary: Clean Architecture
→ Supporting: Refactoring

PostgreSQL / ClickHouse outage and recovery
→ Primary: Release It!
→ Supporting: Designing Data-Intensive Applications

Large legacy cleanup
→ Primary: Working Effectively with Legacy Code
→ Supporting: Refactoring

main.py or frontend modularization
→ Primary: Refactoring
→ Supporting: Clean Architecture
```

If one requested task spans multiple concerns, split it into independently testable phases and select skills separately for each phase.

Skill selection never bypasses the approval gate.

---

## Simplicity Rule

Prefer the smallest architecture that satisfies measured needs.

Do not add by default:

- Kafka
    
- Redis
    
- microservices
    
- another SQL database
    
- another ML detector
    
- LLM in the ingest path
    
- React rewrite
    
- automatic IP blocking
    
- firewall control
    
- remote command execution
    

Current preferred architecture is:

```text
WebSocket Collector
        ↓
ClickHouse raw events
+
PostgreSQL mutable state
        ↓
Rules / Isolation Forest / statistical detectors
        ↓
FastAPI
        ↓
SSE Dashboard
```

Build new functionality around this architecture unless measurements prove it insufficient.