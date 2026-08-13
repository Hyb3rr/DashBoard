# IP Intelligence MVP

Read-only IP enrichment hub. No remote server control, blocking, or remediation.

## Project layout

```text
app/
  main.py                 FastAPI app and HTTP endpoint orchestration
  config/                 Project-relative runtime paths
  core/                   Database, enrichment, classification, and log logic
  services/               Reusable application services
  tools/                  Calibration and Tor refresh CLIs
  dashboard.html          Dashboard view
  ip_detail.html          IP investigation view
  regions.html            Region profile index
  region_detail.html      Country context and market-score detail
data/                     Local databases, seed data, and cached Tor list
tests/                    Unit and endpoint tests
```

The HTTP layer stays in `main.py`; reusable profile storage and enrichment
composition belongs in `app/services/`, while provider and domain logic stays
in focused modules. This keeps new API routes from duplicating persistence
rules or classification wiring.

## Run

```bash
cd ip-intelligence
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000`.

The dashboard can import the local sample `apache_logs.log`, parse Apache
combined access logs, aggregate behavior per IP, enrich new public IPs, and show
a multi-IP security table.

Manual lookup still exists at `GET /api/ip/{ip}`.

Lookup uses the configured MaxMind GeoLite2 databases and cached Tor exit list.
No remote enrichment API or optional provider is enabled in this MVP.

Each cached profile keeps separate layers: geo, network/ASN, privacy flags,
organization confidence/evidence, reputation placeholders, and observed behavior.
The current provider cannot prove that a network organization is the visitor's
identity; `organization_confidence` describes enrichment confidence only.
`network_type` is deliberately conservative (`cdn`, `hosting/datacenter`, or
`isp/unknown`). VPN and proxy signals remain `Unknown` unless a future provider
is explicitly added.

Optional provider configuration:

```text
MAXMIND_CITY_DB=/absolute/path/GeoLite2-City.mmdb
MAXMIND_ASN_DB=/absolute/path/GeoLite2-ASN.mmdb
TOR_EXIT_LIST_PATH=/absolute/path/tor_exit_nodes.txt
TOR_EXIT_LIST_URL=https://check.torproject.org/torbulkexitlist
```

Core provider priority is field-aware and local-first:

```text
Cache
→ MaxMind GeoLite2 City/ASN
→ Tor local list
→ local organization/network heuristics
```

Use `GET /api/ip/{ip}?refresh=true` to explicitly refresh one cached profile
after adding/changing local databases or provider configuration.

Profiles now separate `core_enrichment_status`, `privacy_enrichment_status`, and
`threat_enrichment_status`. Backward-compatible `enrichment_status` follows core
status so optional provider outages do not downgrade otherwise-good local
Geo/ASN results. Unknown privacy signals remain SQL `NULL` and display as
`Unknown`, not `No`.

## API

```text
GET  /health
GET  /regions
GET  /regions/{country_code}
GET  /api/ip/{ip}
GET  /api/ips?limit=500
GET  /api/ips/calibration.csv
GET  /api/regions?limit=50
GET  /api/regions/{country_code}
GET  /api/regions/demand-signal?limit=50
POST /api/ips/refresh-unknown?limit=100
POST /api/import/sample?mode=replace
```

Region profiles return economic, cultural, and normalized conflict indicators.
Conflict fields are `type`, `severity`, `source`, `date`, and `description`,
plus available provenance metadata. `severity` is `low`, `medium`, `high`,
`critical`, or `null` when unknown. Legacy `label`, `value`, and `data_date`
aliases remain available for existing clients. Invalid or missing context
degrades to unknown data instead of failing the response.

Every region response contains a batch-precomputed woodworking machinery market score:

```text
economic_potential       40%
machine_demand             60%

economic_potential = market_capacity × 40% + industrial_fit × 60%

woodworking_machine_demand:
  HS8465 import size 55%
  3-year growth      25%
  stability          10%
  product breadth    10%

market_capacity uses GDP, GDP per capita, merchandise imports, and population
at 25% each. Forest is a supporting Industrial Fit signal with 5% internal
weight.

market_score = economic_potential × 40% + machine_demand × 60%
```

Score levels are `low` (0–24), `medium` (25–49), `high` (50–74), and
`very_high` (75–100). Missing structured signals return `market_score: null`
and `market_level: unknown`. `market_evidence` exposes each contribution,
source, date, raw value, percentile, points, weight, and effect. This
commercial score never changes `threat_signal_score`.

Refresh local market intelligence with:

```bash
python -m app.tools.market_refresh
```

The refresh reads `data/worldbank/Data.csv`,
`data/worldbank/Series _Metadata.csv`, and all yearly CSV files in
`data/comtrade/`. Comtrade data currently ends at 2025; no 2026 data is
assumed.

`/api/regions/demand-signal` is an observed-traffic signal for market
exploration, not a claim about a person or a country's demand. It joins the
country profile with IPs classified `good`, then reports qualifying good
traffic after excluding Tor/VPN/proxy/hosting signals, bots, and sensitive
probes. Validate it with conversion, customer, and product analytics before
making business decisions.

Responses include `field_sources`, `provider_status`, `core_enrichment_status`,
`privacy_enrichment_status`, and `threat_enrichment_status`.

To test one previously cached IP:

```bash
curl 'http://127.0.0.1:8000/api/ip/8.8.8.8?refresh=true'
```

To refresh old failed/partial/unknown profiles:

```bash
curl -X POST 'http://127.0.0.1:8000/api/ips/refresh-unknown?limit=100'
```

Refresh the local Tor exit list safely. The command uses ETag and
Last-Modified when available, validates that the response contains public IPs,
and atomically replaces the old file only after validation succeeds:

```bash
python -m app.tools.tor_refresh
```

The refresh job never contacts or changes a monitored website. If the download
fails or is empty, the previous Tor list remains in place.

Automatic scheduling is intentionally deferred until the deployment target is
known. No cron, systemd, or launchd job is registered by this repository yet.

To calibrate classification with real traffic, export the current predictions:

```bash
curl -o ip-calibration.csv 'http://127.0.0.1:8000/api/ips/calibration.csv'
```

Fill the `human_label` column manually using only `good`, `watch`, `bad`, or
`unknown`. Keep the existing columns so the mismatches retain their evidence.
Then evaluate the labeled rows:

```bash
python -m app.tools.calibration ip-calibration.csv
```

The report includes accuracy, per-label precision/recall, a confusion matrix,
and the IPs where the system disagrees with the human label. Blank labels are
ignored, so calibration can be done incrementally.

Classification uses four auditable groups: behavior A (primary and sourced
from `ip_observations.behavior_score`), identity B (capped at 25), trust C, and
region D (capped at 5 and only enabled when behavior exists). `risk_score` and
`effective_risk_score` are not inputs to classification, preventing
double-counting. Sensitive-path probing is a hard behavior signal; low-volume
IPs without A/B evidence remain `unknown`.

`/api/import/sample` reads only the local sample log file. Enrichment remains a
separate local-only operation through `/api/ips/refresh-unknown`. Neither route
connects back to, configures, blocks, or executes anything on the monitored
website.

## Stored Data

```text
events            raw normalized log events
ip_profiles       stable IP enrichment cache
ip_observations   behavior aggregate per IP
region_profiles   sourced country context stored as local JSON fields
```

## Design limits

IP location is approximate. VPN/proxy/hosting detection is probabilistic. An IP
does not identify a person. Economic, cultural, and conflict data must be joined
from reputable country-level datasets and shown with source, date, and confidence;
this MVP stores that profile separately and does not infer culture or danger from
an IP alone.

Run tests with:

```bash
pytest -q
```

Manual verification:

```bash
uvicorn app.main:app --reload
curl 'http://127.0.0.1:8000/api/regions?limit=5'
curl 'http://127.0.0.1:8000/api/regions/US'
curl 'http://127.0.0.1:8000/api/ip/8.8.8.8'
```

Then open `http://127.0.0.1:8000/regions` and follow a country into its detail
page. World Bank ingestion and LLM explanations remain future work; runtime
still reads only local region data.
