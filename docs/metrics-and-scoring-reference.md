# Sentinel Hub — Metric and Scoring Reference

This document explains the numeric values currently produced or displayed by
the application. It follows the implementation in this repository; where a
stored snapshot, selected time range, or current code path changes the meaning,
that scope is called out explicitly.

## How to read the numbers

- A **score** is a model output with a defined scale and formula. It is not
  automatically a probability or a calibrated measure of correctness.
- **Confidence** must always name what it refers to. Classification confidence,
  geo-source confidence, traffic-validity confidence, market confidence, and
  evidence coverage are different values and are not interchangeable.
- **Counts and ratios** need their time window and filters. An IP counter in a
  PostgreSQL read model may cover its retained observation history, while a
  traffic chart is queried from ClickHouse for the selected event-time range.
- Missing evidence is generally represented as unavailable/unknown rather than
  as an observed zero. Some formulas renormalize weights across available
  inputs; consult the row below before comparing scores.
- Market and geography scores describe market/context evidence. They do not
  contribute to an IP security verdict unless a specific security formula says
  so.

## Security and IP metrics

### Family-max scoring rollout

`app/core/shadow_scoring.py` defines the evidence-family map and pure
aggregation helper. The runtime wrapper in `app/services/classification.py`
compares the V1 behavior score with family-max from the already selected
`detections_recent` on classification calls. Phase A records process-local
aggregate counters/gauges; shadow results do not affect classification,
alerts, or disposition.

Production classification always uses family-max for behavior component A: the sum
of the maximum points in each family, clamped to 0–100. V1 behavior points are still
computed for comparison, but there is no runtime switch back to V1; rollback requires
reverting the code change. Existing rule IDs/points, identity/trust/region/AI
components, thresholds, hard-sensitive Critical logic, and confidence are preserved.
If `detections_recent` is unavailable, classification falls back to V1 and records a
missing-input metric.

Metrics are process-local at `/metrics`; counters summarize observation counts,
V1/family-max points, delta direction/magnitude and active mode. They carry no IP labels
and reset when the process restarts. The observed Phase B production cutover recorded
128 family-max classifications with zero delta; all had behavior score 0, so this
validates runtime operation but does not exercise correlated-rule cases or establish
accuracy. Family-max remains unvalidated against human-labelled ground truth.

The candidate formula sums the maximum contribution within each family, then
clamps the result to 0–100. The offline scorer retains correlated evidence in
`raw_evidence`; `correlation_adjustments` records points removed by same-family
deduplication or the final clamp. FireHOL AbuseIPDB 1-day and 30-day feeds are
one reputation family, not independent sources.

| Evidence family | Current rule/provider members | Correlation handling |
|---|---|---|
| Traffic rate | `WEB-RATE-001`, `WEB-BURST-001` | Same family; keep both raw records and use the maximum contribution. |
| HTTP error activity | `WEB-4XX-001`, `WEB-BOT-001` | Same family; bot errors overlap the broader 4xx signal, so use the maximum. |
| Reconnaissance | `WEB-SCAN-001`, `WEB-SENSITIVE-001` | Same family; path enumeration and sensitive-path probes can describe one scan, so use the maximum. |
| Credential attack | `WEB-BRUTE-001` | Separate family. It may coincide with traffic-rate or HTTP-error activity; current rules do not establish event overlap, so the scorer records this as review-only and applies no cross-family discount. |
| Abuse reputation | `firehol:abuseipdb_1d`, `firehol:abuseipdb_30d` | One reputation family; use the maximum so the two time windows are not counted as independent sources. |

The output includes `family_scores`, `raw_evidence`, `correlation_adjustments`,
`missing_evidence`, `unmapped_evidence`, and `final_score` so a later backtest
can trace both included and suppressed points. Missing or unmapped evidence is
not silently converted into a negative signal. The offline report is
experimental; the runtime classifier uses family-max without a runtime mode switch.

### Offline historical comparison

Run `python -m scripts.ops.shadow_backtest data/ai/corpora/foundation-sec-real.json`
to compare saved CasePacket snapshots. The CLI reads JSON files only and prints
deterministic JSON to stdout; it does not query PostgreSQL/ClickHouse, contact a
network service, write a report file, or change runtime state. Multiple saved
corpora can be supplied to form one paired cohort.

The comparison uses the persisted `classification.risk_score` from each packet
as V1. It does not recompute historical V1 with the current classifier. The
report records the packet IP, case ID, evidence fingerprint, snapshot time,
source file/hash, corpus hash and builder version. If the packet does not
contain a persisted V1 score, it is skipped with a reason. The current corpus
format does not record the classifier scoring version separately; reports mark
that version as unrecorded instead of treating the corpus builder version as a
classifier version.

The report pairs only usable packets and includes V1/shadow summaries, the
`shadow − V1` delta distribution, exact numeric-score agreement, disagreement
cases with evidence/family breakdowns, family coverage, missing and unmapped
evidence, and same-family correlation points removed. Exact agreement refers to
the numeric scores only; no shadow label or threshold is inferred. This
CasePacket corpus is selected for case review and **is not representative of
the production IP population**. Family coverage also remains unknown when a
packet has neither evidence nor an explicit available-family declaration.

New corpora also carry a root-level `score_comparison_snapshots` sidecar keyed
by `case_id`. It preserves the selected persisted `detections_recent` window,
recent behavior inputs, network flags, trusted-organization inputs, persisted
V1 label/score/confidence, and available ruleset hashes without changing the
CasePacket sent to the AI explainer. Missing selected detections remain
explicitly unavailable; the builder does not substitute the 24-hour list.
`capture_classifier_fingerprint` fingerprints current classifier/confidence
source files at corpus-build time. It is not proof of which code produced an
older persisted V1 score: classification persistence does not currently store
that version, so the sidecar marks it as unrecorded. Older corpora without this
sidecar remain partial-input comparisons.

The report marks this as a **partial-input score comparison**, not a controlled
scoring-policy comparison. New corpora capture the selected persisted behavior
window, network flags, trusted-organization inputs, and available ruleset hashes
in the sidecar above. The shadow scorer still consumes only CasePacket evidence,
so these captured inputs are currently adequacy/provenance data and are not yet
used to calculate its score. Older corpora have no sidecar. Persisted V1
classifier version is not stored; a current-source fingerprint cannot establish
which version produced an older score. The report joins available sidecars by
`case_id`, preserves the sidecar on each usable case, and summarizes field
coverage under `comparability.future_v1_input_capture`. Therefore total score
delta is not attributable to family deduplication alone and must not be used to
select weights. `correlation_adjustments` separately reports points the shadow
formula actually removed within a family; that direct attribution remains
interpretable when overall input coverage is partial.

Machine-readable `comparability` fields carry these limits in each report.
`snapshot_at` comes from `packet.window.end`; `corpus_created_at` is reported
separately as the time the corpus artifact was produced.

| UI metric | Meaning and current calculation | Source and scope | Interpretation limit |
|---|---|---|---|
| **Risk score** (`/100`, API field `classification.score`) | `clamp(A + B + C + D + E, 0, 100)`. A is the recent behavior score. B adds Tor +15, proxy +10, VPN +8, hosting +5, capped at +25. C can subtract 20 for an attributed organization with confidence ≥70%, not hosting, and A <25. D adds up to +5 for qualifying region conflict, only when A >0. E adds +8 when A <25, AI anomaly score ≥70, and at least 3 AI windows exist. | Computed by `app/core/intelligence.py`; the current label/score is persisted in PostgreSQL classification state and returned by the IP state/detail APIs. The dashboard may also expose it as `effective_risk_score` / `threat_signal_score`. | This is the authoritative deterministic classification score, **not a probability that the IP is malicious**. The classifier supports region (D) and AI (E) contributions, but all current persisted classification paths pass empty region context and no AI profile, so D and E do not affect the stored production verdict. Hard sensitive probing can classify Critical independently of the ordinary numeric threshold. |
| **Classification label** | `unknown` when requests <3 and there are no behavior, identity, or AI points; otherwise Critical for sensitive probing or base score ≥60; Medium for final score ≥30 or an eligible AI bonus; Low for score ≥10; otherwise Good. | Same classifier and persisted PostgreSQL state as above. | The label is not just a bucketization of the final score: the hard-probe and unknown rules are additional conditions. |
| **Behavior / rule score** (`/100`) | Sum of deterministic behavior-rule points, capped at 100. Features include request volume/bursts, 4xx ratio, unique paths, sensitive probes and other rule-specific evidence. | `app/db/detection_repository.py` builds one-hour and recent/24-hour observations from PostgreSQL detection features and runs `app/core/rules/`. | This is input A to classification, not the final classification score. The rule level thresholds (low <25, medium <55, high <80, critical ≥80) are rule-score levels, not the IP classification label thresholds. |
| **Assessment confidence (heuristic)** (`%`, API field `classification.confidence`) | Base by label: Critical 90, Medium 75, Low 70, Good 65, Unknown 35. Add +5 for complete core enrichment, +5 for complete privacy enrichment, +8 for high AI confidence (or +4 for medium), and +5 for rule-history coverage; clamp to 0–100. | `app/core/telemetry.py`; included in classification output and persisted in PostgreSQL. Rule coverage is explicit when available, otherwise derived from at least 24 hours of bucket history. Current persisted classification paths do not pass an AI profile, so the AI-confidence adjustment is not applied to stored confidence. | A completeness/confidence heuristic, **not a verified probability or proof that the IP is trustworthy**. Enrichment completeness only says the data pipeline has more of its expected inputs; it does not independently validate the verdict. Current implementation does not establish statistical calibration against labelled outcomes. |
| **Network context** (`/100`, API fields `profile_risk_score` in dashboard projections and `risk_score` on IP Detail) | Separate profile score derived from local Tor (+55), proxy (+35), VPN (+30), and hosting/datacenter (+20) signals, capped at 100. | `app/core/enrichment_policy.py` computes the profile value; `app/routers/ip_state.py` exposes the dashboard projection. IP Detail uses the profile's `risk_score` field. | Context about privacy/hosting infrastructure only. It is **not a verdict**, does not define Good/Low/Medium/Critical, and must not be confused with the authoritative Risk score. |
| **Classification history / highest recorded** | A list of persisted classification transitions, with before/after label and score plus evidence when retained. Highest recorded is the maximum historical severity represented by retained transitions/current state. | PostgreSQL classification history and change-log/alert backfill; IP Detail API. | Historical peak is not the current classification and does not imply the old signal is still active. Older backfilled transitions may lack detailed evidence. |
| **Requests, 4xx, 5xx, unique paths, first/last seen** | Counts and timestamps in the IP observation read model. IP Detail 4xx ratio is `round(4xx / requests × 100)` when requests >0. | PostgreSQL observation payload/read model. The IP Detail traffic chart, status breakdown, paths, and recent requests instead query ClickHouse for the selected range. | The UI should state whether a number is the stored IP observation or a selected ClickHouse time window; those scopes can differ. |
| **Geo/network confidence and disagreement** | Geo resolution ranks source candidates using source reliability/weights; country/city/coordinate confidence and dispute status are distinct. Coordinate confidence can be reduced by distance disagreement and must clear a resolve threshold. | `app/services/geo_resolution.py`, `app/db/pg_intelligence.py`, PostgreSQL geo-resolution/profile state. Source-level candidates are exposed in IP Detail. | Geo confidence concerns location attribution only. RIR registration country is not physical location; a confidence percentage is not a guarantee. |
| **Signal tags** | Labels such as HOST, PROXY, TOR, VPN, ABUSE PERSISTENT/HISTORICAL, or UNKNOWN summarize source/rule evidence. | PostgreSQL profile/intelligence and behavior evidence projections; UI renders tags from returned signals. | Tags are not all score contributions. A tag may be contextual or historical and should not be read as an active detection without its evidence/time semantics. |
| **Alert counts and severity** | Number of alert records matching the selected severity/status/time filters; severity is the stored alert field. | PostgreSQL alert repository and alert APIs. | Alert count is not request count, unique IP count, or necessarily current IP classification count. |
| **Triage disposition** | Analyst workflow state (for example New, Monitor, Investigate, Escalate, Resolved), not a calculated security score. | PostgreSQL disposition state. | It records analyst handling and must not be interpreted as an automated verdict. |

### Worked IP examples

These examples use values visible in the current product screenshots/source
history and are explanatory snapshots, not a claim about the live database now.

1. The Overview screenshot showed **59 IPs** split into Critical 1, Medium 1,
   Low 4, Good 46 and Unclassified 7. Those values sum to 59. The donut counts
   distinct IPs in the exact ClickHouse event cohort for the selected range,
   then joins each IP to its latest PostgreSQL classification; absent state is
   counted as Unknown. Thus the cohort is time-bounded, while the label is the
   latest state and may have been updated after the event.
2. The IP Detail example for `123.20.209.162` showed a current Good score of
   0/100 and a retained earlier transition from Good 0 to Medium 30. Its
   historical evidence cited a burst (+20) and sustained rate (+10). This
   illustrates that the current window can recalculate lower while the
   transition remains in history; the peak is not a sticky current score.
3. Classification confidence example, calculated from the current formula:
   Good base 65 + core enrichment 5 + privacy enrichment 5 + high AI confidence
   8 + rule coverage 5 = **88/100**. The number means the implementation's
   completeness-adjusted confidence heuristic; it does **not** mean an
   independently verified 88% chance that the classification is correct.

## Overview and traffic analytics

| UI metric | Current calculation | Source and scope |
|---|---|---|
| **Total requests** | Count of matching HTTP event rows. | ClickHouse `http_events FINAL`, selected event-time range, dataset and active filters. |
| **2xx / 3xx / 4xx / 5xx** | Count by HTTP status range; 4xx is 400–499 and 5xx is ≥500. | Same ClickHouse query cohort. |
| **Errors** | Count of events with status ≥400 (4xx + 5xx). | Same ClickHouse range/filter. |
| **Unique IPs** | Exact distinct source-IP count (`uniqExact`). | Same ClickHouse range/filter. |
| **Top IPs / Top paths** | Group matching events by source IP or path, sort by request count descending (stable IP/path tie-break), return up to 8; UI currently shows up to 6. | ClickHouse, same range/filter. A top-list count is requests, not risk. |
| **Top countries** | Sum each observed IP's request count into its currently resolved PostgreSQL country; return the top 8. | ClickHouse request counts joined to PostgreSQL country profiles. This joins event-time traffic to current profile location. |
| **Traffic timeline** | Requests per selected bucket; errors per bucket are status ≥400. Low/Medium/Critical overlays sum per-IP minute-feature requests for IPs with those current PostgreSQL labels. | ClickHouse total/error series plus PostgreSQL `ip_minute_features` joined to current classification. Path-filter risk overlay is intentionally unavailable. Cross-store data is not one atomic snapshot. |
| **Classification donut** | Distinct IPs in the exact raw-event cohort, counted by current PostgreSQL label; missing/delayed label becomes Unknown. If filtering to a class, the donut shows that selected class cohort. | ClickHouse cohort membership + PostgreSQL current classification. This is not classification-at-event-time. |
| **Time buckets / range** | Presets range from 30 minutes through 30 days; bucket size depends on selected range, with custom windows choosing a bounded bucket. | API `/api/analytics/traffic`; response includes start/end, range, bucket and `as_of`. The selected window and filters should accompany displayed numbers. |

## Country, region, and market metrics

The application has several different market/geography models. A generic label
such as “Region Score” is ambiguous and should be replaced by the exact metric
name below.

| Metric | Current calculation | Source and scope | Interpretation limit |
|---|---|---|---|
| **Country demand strength** | Weighted qualified traffic is compressed logarithmically: `min(100, 100 × log1p(weighted) / log1p(100))`. | Batch country-demand snapshots from ClickHouse behavior/session observations, selected 7d/30d/90d period. | Depends on traffic qualification policy and chosen reference 100; it is not raw visits. |
| **Engagement quality** | `100 × (0.45 × engaged_rate + 0.30 × page_depth + 0.25 × key_event_rate)`. Page depth is capped at 5 views per identity; only observations with engagement evidence are used. | Country-demand batch snapshot. | Missing engagement evidence affects coverage; this is a product-specific signal, not a universal analytics standard. |
| **Momentum** | Period growth is `(current_weighted − previous_weighted) / previous_weighted × 100`; score is `clamp(50 + growth, 0, 100)`. | Current vs previous demand window. | Unavailable when previous weighted demand is zero or absent. |
| **Country demand score** | Weighted blend: strength 50%, engagement quality 30%, momentum 20%; missing quality/momentum is excluded and remaining weights renormalized. | `app/core/country_demand.py`. | Keep demand score separate from traffic counts, market score and confidence. |
| **Demand confidence** | Engagement-evidence coverage × sample damping. Sample damping is logarithmic based on the smaller of current/previous weighted sessions relative to 30; zero if no previous sample. | Same country-demand snapshot. | A heuristic evidence-coverage value, not calibrated probability. |
| **Qualified requests / evidence tier / traffic strength** | Qualified request count is raw selected-period demand input. Evidence tier thresholds are 1, 10, 30 and 100 requests; traffic strength is the country's relative request-volume percentile among observed countries. | Country-demand snapshot; 7d/30d/90d. | Tier and rank depend on cohort size and selected period; percentile is relative to this observed cohort. |
| **Adjusted demand** | `50 + demand_confidence × (country_demand_score − 50)`; low confidence shrinks the demand toward neutral 50. | Country opportunity response. | 50 is a neutral shrinkage baseline, not an observed market value. |
| **Country opportunity score** | `0.60 × market_score + 0.40 × adjusted_demand`, only when both inputs exist. Status (Prioritize/Emerging/Investigate/Watch/Low Priority) applies additional score, demand, and confidence thresholds. | `/api/country-opportunities`, persisted market profile plus published demand snapshots. | Composite country-level prioritization; not a security score, sales probability or guaranteed opportunity. |
| **Country market score** | Current API reads a batch-precomputed score/components/evidence snapshot. A legacy schema-v0 fallback, if encountered before refresh, combines market-capacity and demand-fit tiers at 50/50 using tier-to-point conversion. | PostgreSQL country region/market read model, populated by market refresh. | Inspect `score_status`, `missing_reason`, year, method, confidence and component provenance. New schema formula should be read from its published `market_evidence`, not inferred from the legacy fallback. |
| **Country product prior** | Available normalized country signals weighted: HS imports 35%, relevant exports 20%, sector consumption 20%, manufacturing growth 10%, labor-cost pressure 10%, cement consumption 5%; missing inputs are removed from the denominator. At least 3 of 6 signals are required for a snapshot score. | `app/core/market_potential.py`; woodworking/metalworking product categories. | Product-specific prior; normalized inputs and source years matter. |
| **City fit** | Requires normalized business density and relevant-sector share; optionally includes industrial-cluster flag. The resulting raw value is ranked as percentile against peer cities and expressed 0–100. | Market potential evidence/read model. | Relative to the peer cohort and available city evidence; not a standalone demand count. |
| **Sales validation** | Weighted RFQ count 25%, quotation response 20%, win rate 25%, average deal value 20%, repeat purchase 10%; resulting value is ranked against peers. | Internal RFQ/sales signals in market-potential read model. | Missing inputs are renormalized; score depends on peer group and data coverage. |
| **Product market-potential score** | External country/city evidence defaults to 60/40. Internal sales weight rises as `min(1, log(1 + rfq_count_12m) / log(1 + k))`, default `k=20`; available external sources renormalize their share. | Market-potential snapshot, separate from Country Opportunity. | `score_type` distinguishes prior, estimated and observed. Do not describe the number simply as a generic region score. |
| **Market-potential confidence** | 40% signal-group coverage +25% freshness +20% source quality +15% internal-validation-present, with normalized inputs. | Market-potential calculation. | Confidence of this model's evidence, not outcome probability. |
| **Province/city Overall opportunity** | Current `city-overall-v1` snapshot ranks available inputs against peers using percentiles. Groups: enterprise base 25%, IIP 15%, FDI flow 15%, FDI stock 15%, local presence 7.5%, park count 7.5%. Missing groups are omitted and weights renormalized. Coverage reports the available original weight share. | Published PostgreSQL city-overall snapshot; province profile joins its score, components, version, peer group and snapshot metadata. | This score exists in current runtime/UI despite older project-context text saying no composite Province Potential Score. Treat it as a versioned evidence-first relative score, not purchase probability or an approved universal “province potential” measure. |
| **Province enterprise base / IIP / FDI** | Raw published counts, year-over-year IIP, current-period FDI flow and cumulative FDI stock; UI may rank observed enterprise values into High/Moderate/Limited relative tiers. | Province profile/source snapshots, including enterprise registry proxy, NSO and FDI sources where available. | Preserve source, geography, unit, period, transformation and limitations. Enterprise registry count is a proxy, not an official factory count; published zero differs from missing. |
| **Map requests, IP classes, coverage** | Request totals and class counts follow selected map range and country/city read model; located/unlocated coverage compares mapped evidence with observed totals. | ClickHouse traffic plus PostgreSQL geo and map read models. | Map markers can summarize a bounded read model; check response `range`, `generated_at`, coverage and layer (Opportunity/Threat). Opportunity and threat colors are separate semantics. |

## Operations, logs, and other displayed numbers

| UI metric | Meaning | Source and scope |
|---|---|---|
| **Raw Log Tail loaded lines** | Number of rows currently loaded/rendered from the chosen history window and active IP/status filters, not total archive size. | Bounded ClickHouse raw-event query; response has `window_seconds`, fixed `as_of`, cursor and `has_more`. |
| **HTTP status / method / event time / IP in a raw line** | Parsed display of each stored event's request evidence. | ClickHouse `http_events`; status is the event response code, timestamp is event time. |
| **System health / Live / Degraded** | Composite operational status across rules, PostgreSQL, ClickHouse, collector/archive/parser/privacy state, classification watcher and realtime listener according to health policy. | `/health` and collector status APIs. | It is a readiness/health state, not a numeric reliability percentage or a security score. Individual subsystem status is more diagnostic than the aggregate label. |
| **Realtime latency / updated at / as-of** | Pipeline or query timestamps reported by their owning endpoint/read model. | API response and PostgreSQL/collector state. | Different cards may have different refresh cadence and clocks; show the timestamp corresponding to the number rather than implying one global refresh instant. |

## Worked market examples

These are arithmetic examples using the implemented formulas, not current live
country/province database values:

1. If market score is 70, country demand is 80 and demand confidence is 0.25,
   adjusted demand is `50 + 0.25 × (80 − 50) = 57.5`; country opportunity is
   `0.60 × 70 + 0.40 × 57.5 = 65.0`.
2. If a province has normalized peer percentiles for enterprise base 80 and
   IIP 60 only, current available group weights are 0.25 and 0.15. The score
   is `(80×0.25 + 60×0.15) / 0.40 = 72.5`; evidence coverage is 40%. This is
   relative to the published peer snapshot, not an absolute 72.5% chance.

## Source map

- IP classification and risk components: `app/core/intelligence.py`.
- Classification completeness/confidence: `app/core/telemetry.py`.
- Behavior aggregation/rule score: `app/db/detection_repository.py`,
  `app/core/rules/`, and `rules/behavior/`.
- IP state projections: `app/routers/ip_state.py`,
  `app/db/state_repository.py`, `app/services/profiles.py`.
- ClickHouse traffic and raw logs: `app/db/clickhouse.py`,
  `app/routers/traffic.py`, `app/routers/raw_logs.py`.
- Country demand and opportunity: `app/core/country_demand.py`,
  `app/services/country_demand.py`, `app/db/market_demand_repository.py`,
  `app/routers/regions.py`.
- Country and product market scores: `app/core/regions.py`,
  `app/core/market_potential.py`, `scripts/market/market_refresh.py`.
- Province profiles and overall score: `app/services/province_profile.py`,
  `app/core/city_overall_opportunity.py`, `app/services/city_overall_snapshot.py`,
  `app/db/market_repository.py`.
- Geography confidence: `app/services/geo_resolution.py`,
  `app/db/pg_intelligence.py`.
- Alerts and system health: `app/db/alert_repository.py`,
  `app/routers/alerts.py`, `app/routers/health.py`.

## Documentation and product follow-up

This is a source-backed reference, not yet a UI tooltip implementation. For a
future interface, explain a value at the point of use with its exact metric
name, source, time range/snapshot, formula or counting rule, last update, and
missing-data caveat. The highest-priority values are classification score and
confidence, Country Opportunity, country market score, province/city Overall
opportunity, and the Overview classification donut. Avoid calling any of these
“IP trust score” or “probability” unless a separately validated model defines
that meaning.
