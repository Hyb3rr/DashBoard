# 1 IP Intelligence Hub

> Local-first security dashboard for observed web traffic, IP enrichment,
> behavior scoring, threat intelligence and investigation workflows.

The application observes normalized access-log traffic, enriches public IPs,
calculates auditable signals and presents the result in a dashboard. It is
defensive monitoring software: it does not control remote servers, block
traffic, run exploit tools or identify a person behind an IP address.

## 1.1 1. System overview

~~~text
                    Dashboard / UI
          overview · IP case · region profiles
                         |
                    HTTP / SSE
                         |
                 FastAPI application
                       app/main.py
                         |
          +--------------+---------------+
          |                              |
      PostgreSQL                 background workers
 state, profiles,               WebSocket, Intel,
 classification, alerts         classification, Telegram
          |                              |
          +--------------+---------------+
                         |
                 source files and feeds
        logs · GeoIP · RIR · VPN/proxy · FireHOL
~~~

### 1.1.1 Main data flow

~~~text
WebSocket / Apache log
        |
        v
parse + normalize + deduplicate
        |
        +-- events              raw forensic request
        +-- ip_time_buckets     minute traffic aggregate
        +-- ip_path_stats       lifetime path aggregate
        +-- ip_observations     behavior and detection snapshot
        +-- ip_change_log       incremental dashboard/watchers

new or refreshed IP
        |
        v
local enrichment lookup
        |
        +-- ip_profiles         cached profile
        +-- geo_resolutions      location and provenance
        +-- classification       threat label and score
        +-- alert_outbox         durable Telegram delivery
~~~

## 1.2 2. Repository structure

~~~text
app/
├── main.py                     FastAPI app and API orchestration
├── dashboard.html              Global traffic/IP dashboard
├── ip_detail.html              Single-IP investigation view
├── regions.html                Region profile index
├── region_detail.html          Country/market detail
├── config/settings.py           Runtime paths and environment loading
├── core/                       Database and domain logic
├── providers/                  External-source adapters and cache parsers
├── services/                   Profiles, classification, coverage, Telegram
├── collectors/                 Resumable live log collector
├── ai/                         Bucket features and Isolation Forest
└── tools/                      Refresh, scheduler and calibration commands

data/
├── postgres/                   PostgreSQL runtime data
├── clickhouse/                 ClickHouse runtime data
├── models/                     Last-known-good AI artifacts
├── geo/                        RIR/geofeed/BGP caches
├── intel/                      VPN/proxy/threat-feed caches
├── tor_exit_nodes.txt          Local Tor exit list
└── region_profiles.seed.json   Local region seed data

tests/                          Unit, integration and replay tests
.env.example                    Configuration reference
requirements.txt                Runtime/test dependencies
~~~

Core module responsibilities:

| Module                             | Responsibility                                            |
| ---------------------------------- | --------------------------------------------------------- |
| db/postgres.py                     | PostgreSQL connection and schema management              |
| db/repositories.py                 | PostgreSQL state repositories                            |
| db/clickhouse.py                   | ClickHouse traffic storage and analytics                 |
| core/enrichment.py                 | Local-only profile and intelligence lookup                |
| core/intelligence.py               | Auditable A–E threat scoring                              |
| core/geo_resolver.py               | Global network-location resolution                        |
| core/intel_updater.py              | Single external intelligence refresh orchestrator         |
| collectors/websocket_collector.py  | Live log stream, offset resume and reconnect              |
| services/classification.py         | Canonical classification snapshot                         |
| services/classification_watcher.py | Background classification transition watcher              |
| ai/detector.py                     | Isolation Forest training and anomaly scoring             |
| providers/                         | RIR, geofeed, VPN, proxy, FireHOL and cloud sources       |
| tools/                             | Scheduled refreshes and analyst utilities                 |

app/main.py is the current HTTP composition point. New domain logic should be
placed in core, providers or services instead of duplicated in route handlers.

HTTP routes are grouped by domain in `app/routers/`. The first extracted
routers cover health, traffic, IP state/detail, regions, realtime and pages;
`app/main.py` keeps application setup, lifespan and router composition.

PostgreSQL IP read-model routes now live in `app/routers/ip_state.py`.

Dashboard presentation assets live in `app/static/dashboard.css` and
`app/static/dashboard.js`; `dashboard.html` remains the page shell. This is
asset extraction only: layout, filters, charts and realtime behavior stay the
same.

`/health` includes process-local observability counters, gauges and batch
latencies. Ingest and ClickHouse metrics update per committed batch; queue and
reconnect gauges update on status checks. No database write or lock occurs per
event for metrics.

Rare-path shadow batches also expose batch latency, error count and evidence
count through `/health`. They run periodically, not once per incoming event.

## 1.3 3. Runtime pipeline

### 1.3.1 Ingestion

The WebSocket collector is the live event source and uses one normalized event
pipeline. The dashboard is served by FastAPI in live-only mode:

All traffic, IP, snapshot, update and refresh APIs use live PostgreSQL and
ClickHouse state. They do not accept file-mode parameters or select a file
dataset.

~~~text
source input
  -> parse and normalize
  -> source + offset idempotency check
  -> insert events
  -> update ip_time_buckets
  -> update ip_path_stats
  -> rebuild affected ip_observations
  -> append ip_change_log
  -> publish realtime update
~~~

WebSocket events use sources such as `ws:azure-access`. The collector persists
its checkpoint in PostgreSQL. Reconnects resume from the last committed offset,
and duplicate offsets are ignored.

The collector batches pending lines in memory and flushes them when either
`LOG_WS_BATCH_SIZE` is reached or `LOG_WS_FLUSH_MS` elapses (whichever comes
first). The dashboard realtime event is published only after the batch commits;
this keeps small changes visible without writing every individual log line.
The dashboard also synchronizes the durable change cursor every second; SSE is
an acceleration signal, not the sole delivery mechanism. A missed or
cross-process SSE event is therefore recovered on the next cursor sync without
requiring a page reload.
Every committed traffic batch appends a `traffic` change entry, even when the
classification label stays the same, so request-count and last-seen updates
advance the cursor too.

### 1.3.2 Local enrichment

core/enrichment.py never performs HTTP or DNS network I/O. It reads:

~~~text
IP
 ├── MaxMind City / ASN databases
 ├── local geo_resolutions and prefix snapshots
 ├── privacy_networks: VPN / proxy / hosting / Tor evidence
 ├── threat_indicators: FireHOL evidence
 └── cached ip_profiles
~~~

Unknown means no positive evidence was available. It is not silently converted
into a privacy signal.

### 1.3.3 Global network location

The geo layer is global, not Vietnam-specific. It can combine:

- RIR delegated files: APNIC, RIPE, ARIN, LACNIC and AFRINIC.
- Owner-declared geofeeds.
- Optional local pyasn BGP prefix database.
- MaxMind/vendor location data.
- Official cloud/CDN ranges.

The output separates network location, RIR registration context, location
confidence and anonymization signals. RIR registration describes ownership;
it does not automatically override operational location.

### 1.3.4 Intelligence updater

intel_updater.py is the only orchestration point for external HTTP and DNS
intelligence refreshes.

~~~text
due-source trigger
  -> acquire INTEL_UPDATE_LOCK_PATH
  -> conditional download
  -> validate payload
  -> atomic cache replacement
  -> parse and upsert PostgreSQL/ClickHouse state
  -> write intel_source_status
  -> release lock
~~~

Sources include AZ0 VPN, X4B VPN/datacenter, Cloudflare, Device & Browser
Info, selected FireHOL lists, RIR files and configured geofeeds. A failed
optional source does not stop the API or other sources. FireHOL is threat
evidence and does not directly become behavior points.

All live privacy and threat provider refreshes persist through PostgreSQL
(`privacy_networks`, `privacy_network_history` and `threat_indicators`). Feed
caches remain local files; they are input snapshots, not application state.

AI model metadata and per-IP anomaly scores also persist in PostgreSQL
(`ai_model_state` and `ip_ai_scores`). The model artifact remains an atomic local
file snapshot; training and scoring state remain in PostgreSQL.

Manual refresh:

~~~bash
.venv/bin/python -m app.core.intel_updater
~~~

Startup refresh:

~~~env
INTEL_UPDATER_ENABLED=true
INTEL_AUTO_UPDATE_ON_STARTUP=true
~~~

### 1.3.5 Behavior and classification

Behavior uses persisted bucket aggregates and fixed product windows:

~~~text
ip_time_buckets
  -> BehaviorContext for 1h and 24h
  -> detection rules
  -> behavior score and evidence
  -> canonical classification snapshot
~~~

Threat scoring groups:

~~~text
A  behavior       requests, probes, errors and bot patterns
B  identity       Tor/proxy/VPN/hosting support, capped at +25
C  trust          trusted-network reduction for low-risk attributed networks
D  region         small behavior-gated regional nudge
E  AI anomaly     bonus when low rule score has sufficient AI evidence
~~~

services/classification.py is the canonical consumer for Overview, IP Detail,
watchers and alert formatting.

### 1.3.6 AI and Telegram

AI uses bucket features and a persisted Isolation Forest. It is an additional
signal, not a replacement for rule evidence.

Telegram transitions use a durable outbox:

~~~text
classification transition
  -> alert_outbox pending row
  -> claim lease
  -> send
  -> delivered or retry with backoff
~~~

Telegram is disabled by default.

## 1.4 4. Database model

~~~text
RAW
  events

TIME
  ip_time_buckets
  ip_time_bucket_paths

IP SUMMARY
  ip_observations
  ip_profiles
  ip_path_stats

INTELLIGENCE STATE
  geo_resolutions
  privacy_networks
  threat_indicators
  classification, AI, change and outbox tables
~~~

Important tables:

| Table | Purpose |
|---|---|
| events | Raw normalized requests for forensics and recent requests |
| ip_time_buckets | One row per IP/minute for timelines and behavior windows |
| ip_path_stats | Lifetime per-IP path counts/status/first-last seen |
| ip_profiles | Cached enrichment/profile output |
| ip_observations | Lifetime and recent behavior aggregates/detections |
| geo_resolutions | Network location, confidence and provenance |
| privacy_networks | Active VPN/proxy/datacenter memberships |
| threat_indicators | FireHOL evidence |
| intel_source_status | Per-source refresh status and errors |
| ip_change_log | Cursor-based incremental dashboard updates |
| ip_classification_state | Persisted classification transition state |
| rule_firing_state | Detection history by IP/rule/window/ruleset |
| alert_outbox | Durable Telegram delivery queue |
| region_profiles | Country context and market score |

IP Detail reads aggregates for most widgets:

~~~text
summary          -> ip_observations and ip_profiles
timeline/status  -> ip_time_buckets
path activity    -> ip_path_stats
recent requests  -> events LIMIT 50
~~~

## 1.5 5. Web interface

### 1.5.1 Overview

The dashboard provides:

- Live/custom traffic timeline.
- Top IPs, paths and countries.
- Traffic filter/exclude actions.
- Priority queue for bad and watch identities.
- Classification distribution and AI coverage.
- Region market signal.
- Network identity search, sorting and filters.

Widgets load independently. A failed region request does not block traffic;
IP Detail path activity does not block the profile or traffic timeline.

### 1.5.2 IP Detail

The investigation page provides:

- Identity, ASN, organization and first/last seen context.
- Network location and location-confidence explanation.
- VPN, proxy, Tor and hosting signals.
- A–E threat-score explanation and evidence.
- Rare-path supporting evidence with score, first-seen time and explicit
  non-maliciousness caveat.
- Source-specific relative freshness for rules, rare baseline, geo and threat
  intelligence. No generic freshness badge is used.
- IP traffic timeline with start/end controls.
- Status codes, top paths and recent raw requests.
- Provider status and external investigation pivots.

### 1.5.3 Realtime

The dashboard subscribes to /api/stream using Server-Sent Events. Change
notifications trigger incremental IP updates and traffic refreshes. A periodic
fallback refresh keeps the timeline current when an event is missed.

### Rare-path canonicalization

`app/core/path_canonicalization.py` provides the derived path shape for future
rare-path analysis. It removes query strings, collapses repeated slashes, and
replaces complete numeric, UUID, and hash-like segments with `{id}`, `{uuid}`,
and `{hash}`. It preserves path case and trailing slashes.

This value is evidence-only. Raw paths in ClickHouse, live ingest, existing
feature counters, and classification semantics remain unchanged. Rare-path
analysis must consume this derived value in periodic work, never through a
historical ClickHouse query per incoming event.

### Rare-path shadow detector

The background `rare-path-shadow` task scans a rolling seven-day ClickHouse
window periodically, then stores supporting evidence in PostgreSQL observation
state. It calculates population rarity, temporal rarity, and newness into a
`0–100` score. It never runs from ingest flush, never changes BAD/WATCH, and
never treats rarity alone as proof of malicious intent. Raw paths remain
unchanged.

### PostgreSQL pool lifecycle

FastAPI startup calls `open_pool()`, and application shutdown calls
`close_pool()`. Transactions may still open the pool lazily for direct
repository tests that do not run FastAPI lifespan; pytest closes that pool in
`pytest_sessionfinish` so worker threads do not survive interpreter shutdown.

## 1.6 6. API reference

### 1.6.1 Pages

~~~text
GET /                         Overview dashboard
GET /ip/{ip}                  IP investigation page
GET /regions                  Region index
GET /regions/{country_code}   Region detail page
~~~

### 1.6.2 IP and traffic

~~~text
GET /api/analytics/traffic
GET /api/ip/{ip}
GET /api/ip/{ip}/traffic?range=1h
GET /api/ip/{ip}/traffic?start=...&end=...
GET /api/ip/{ip}/paths?limit=12
GET /api/ip/{ip}/attack?window=24h
POST /api/ip/{ip}/disposition
~~~

The IP traffic endpoint returns zero-filled buckets through the requested end
time. Recent raw requests are bounded to avoid loading full history.

`GET /api/analytics/traffic` reads live traffic from ClickHouse and accepts the
existing time-window and filter parameters.

### 1.6.3 Dashboard and realtime state

~~~text
GET /health
GET /api/ips?limit=100
GET /api/ips/snapshot?limit=500
GET /api/ips/updates?after=0&limit=500
GET /api/collector/status
GET /api/stream
~~~

### 1.6.4 Regions and operations

~~~text
GET /api/regions?limit=50
GET /api/regions/{country_code}
GET /api/regions/demand-signal?limit=50
GET /api/ips/calibration.csv
POST /api/ips/refresh-unknown?limit=100
~~~

Examples:

~~~bash
curl 'http://127.0.0.1:8000/api/ip/8.8.8.8'
curl 'http://127.0.0.1:8000/api/ip/8.8.8.8/traffic?range=1h'
curl 'http://127.0.0.1:8000/api/ip/8.8.8.8/paths?limit=12'
~~~

## 1.7 7. Configuration

~~~bash
cp .env.example .env
~~~

| Group | Main settings |
|---|---|
| GeoIP | MAXMIND_CITY_DB, MAXMIND_ASN_DB, MAXMIND_ANONYMOUS_DB |
| Live logs | LOG_WS_ENABLED, LOG_WS_URL, LOG_WS_TOKEN, LOG_WS_LOG_KEY, LOG_WS_SOURCE_ID |
| AI | LOG_WS_AI_*, AI_MODEL_PATH |
| Intel updater | INTEL_UPDATER_ENABLED, INTEL_AUTO_UPDATE_ON_STARTUP, INTEL_UPDATE_LOCK_PATH |
| Device & Browser Info | DEVICEBROWSERINFO_API_KEY, DEVICEBROWSERINFO_CSV_URL, DEVICEBROWSERINFO_AUTH_HEADER |
| VPN/datacenter | AZ0_VPN_MANIFEST_URL, X4B_VPN_LIST_URL, X4B_DATACENTER_LIST_URL |
| FireHOL | FIREHOL_LISTS, FIREHOL_CACHE_DIR |
| Global geo | GEO_RIR_REFRESH_ENABLED, GEOFEED_SOURCES, RIR_*_URL, GEO_PYASN_DB_PATH |
| Tor | TOR_EXIT_LIST_PATH, TOR_EXIT_LIST_URL, TOR_EXIT_LIST_IP1_URL, TOR_EXIT_LIST_REFRESH_HOURS |
| Telegram | TELEGRAM_ALERTS_ENABLED, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID |

Keep secrets in .env or a deployment secret manager. Never commit API keys,
tokens, credentials, brute-force artifacts or provider exports.

## 1.8 8. Running the application

~~~bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
~~~

Open http://127.0.0.1:8000/. PostgreSQL and ClickHouse must be available.

### 1.8.1 Refresh tools

~~~bash
.venv/bin/python -m app.tools.tor_refresh
.venv/bin/python -m app.tools.market_refresh
.venv/bin/python -m app.tools.data_scheduler
.venv/bin/python -m app.core.intel_updater
~~~

The scheduler stores due state in data/update_state.json and avoids overlap
with a lock file. Downloads use conditional headers, validation and atomic
replacement so bad payloads do not overwrite last-known-good data.

## 1.9 9. Testing

~~~bash
pytest -q
python -m compileall -q app
git diff --check
~~~

Tests cover migrations, live replay consistency, offset idempotency,
traffic zero-fill, aggregate path updates, local-only enrichment, global geo,
detection windows, classification consistency and Telegram outbox behavior.

## 1.10 10. Design limits

- An IP is a network identifier, not a person identifier.
- Network location describes infrastructure and may differ from user location.
- RIR country is ownership context, not automatically physical location.
- VPN/proxy/Tor/hosting flags require positive evidence; unknown is valid.
- FireHOL is threat evidence, not automatic behavior-score points.
- AI anomaly detection is probabilistic and should be reviewed with rule evidence.
- Region market scores are commercial context and never change threat scores.
- Optional provider failure is isolated and visible in intel_source_status.

The system supports analyst review and investigation; it is not intended to make
unreviewed claims about people, countries or organizations.

## Split storage (native local test)

The repository now includes the split-storage foundation:

- ClickHouse: raw HTTP events and traffic aggregation.
- PostgreSQL: live state schema for profiles, observations, classification,
  changes and alerts.
- Split storage is the only runtime backend.

Native smoke-test setup (no Docker):

```bash
initdb -D data/postgres --auth=trust
pg_ctl -D data/postgres -l data/postgres.log -o "-p 55432" start
createdb -h 127.0.0.1 -p 55432 ipintel
psql -h 127.0.0.1 -p 55432 -d ipintel -f infra/postgres/001_initial.sql
clickhouse server -- --path="$PWD/data/clickhouse" --http_port=8123 --tcp_port=9001
```

For local development, start both native services and the API with one command:

```bash
./scripts/dev_run.sh
```

The script starts PostgreSQL on port `55432`, starts ClickHouse on port `8123` if
not already running, then launches Uvicorn. `Ctrl-C` stops the API and only the
ClickHouse process started by the script.

Set these runtime values for live operation:

```env
POSTGRES_DSN=postgresql://<user>@127.0.0.1:55432/ipintel
CLICKHOUSE_HOST=127.0.0.1
CLICKHOUSE_PORT=8123
CLICKHOUSE_DATABASE=ipintel
```

`/health` reports both storage connections. In split mode, newly ingested live
raw events are written to ClickHouse before the local offset advances, while
mutable profile, classification and checkpoint state stays in PostgreSQL.
`/api/analytics/traffic` reads its aggregate from ClickHouse.
