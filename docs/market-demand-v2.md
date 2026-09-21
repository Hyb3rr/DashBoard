# Market Demand v2 — Phase 1 inventory

## Contract

Vietnam is the only active market scope. The canonical administrative geography
is the 34 province/municipality catalogue effective 2025-07-01. Province
profiles are the analysis unit; national data remains National Context and is
not allocated to provinces without source-level geography.

The first release describes industrial demand evidence for confirmed Vietnamese
administrative provinces/cities and the 14 machine product groups in the
catalog. It does not publish a purchase probability, a composite market score,
Company Fit, or Buying Signal.

`furniture_export_proxy` remains a source signal for the furniture industry. It
is not a sellable machine and must not be ranked with the other products.

## Evidence rules

- A product mapping is versioned and names the process, target industries, HS
  codes, rationale, source, and specificity (`direct`, `industry_proxy`, or
  `unverified`).
- Country trade data is country context. It is not copied into a province
  record as a province observation.
- OSM or places counts mean observed mapped entities only. They are not a
  census and are not a competition or whitespace score.
- Missing data remains missing. A zero is valid only when the source explicitly
  reports zero.
- Every later evidence row must retain source geography, source period,
  collection time, mapping version, and limitations.
- Historical data before the 2025 administrative change must use the checked
  63-to-34 crosswalk. Counts and totals may be added only when their method
  supports addition. Rates, indexes, shares, and growth values remain at their
  source geography unless a documented methodology supports conversion.
- Freshness belongs to each indicator/source (`reference_period`,
  `retrieved_at`, and source version); a profile must not use one shared
  `latest_complete_year` for unrelated datasets.

## Public-source inventory

| Source | Resolution | Intended use | Current limitation |
| --- | --- | --- | --- |
| UN Comtrade/OEC | country | HS machinery import context | does not identify Vietnamese province demand |
| World Bank WDI | country | manufacturing and investment context | not product-specific or province-level |
| FAOSTAT Forestry | country | wood and panel industry context | applies only to explicitly mapped wood processes |
| ILOSTAT | country | labor-cost context | not a machine purchase label |
| USGS cement | country | cement/construction context | only for explicitly mapped processes |
| OSM Overpass / Places | geo unit | observed mapped industrial entities | incomplete and uneven coverage |
| World Bank FAT Vietnam 2019 | national survey, regional strata | research on adoption drivers | national survey; not a province-level purchase label |
| National Statistics Office statistical data / yearbooks | province and industry tables | industrial context such as operating enterprises, labour, and industrial-production indicators | published aggregates; not a product-level factory registry |
| 2021 Economic Census data warehouse (National Statistics Office) | establishment/enterprise census with configurable geographic and sector breakdowns | candidate source for verified local industry context | requires a reviewed extraction and mapping; not yet ingested into snapshots |
| Internal RFQ/CRM | geo unit | future validation | not available as a public source in this phase |

The Vietnam foundation collector stores raw PX-Web and Comtrade artifacts
under `data/market/vietnam_foundation/` with a manifest. PX-Web enterprise
tables are kept as separate national-industry and province-structure datasets;
the collector never creates an industry-by-province value by allocation.

Canonical geography files: `schemas/vietnam_provinces_2025.json` and
`schemas/vietnam_province_crosswalk.json`. OSM remains Local Discovery Evidence
and is never presented as an official factory registry.

FAT 2019 is nationally representative and stratified by geography, firm size,
and sector. Its eight regions do not provide a general-purpose province-level
label for every product. It can therefore guide feature selection and later
calibration research, but cannot create a city score in this phase.

## Data availability decision

The existing repository has product tracks, country trade files, WDI data,
OSM-derived local features, RFQ fields, and confirmed geo-unit contracts. It
does not yet have a verified province-level source for factory counts across
all 14 product families. Phase 2 must expose that limitation in coverage and
must not fill it with a heuristic zero.

## Phase 2 national foundation

`schemas/vietnam_vsic_taxonomy.json` is the manufacturing-only **VSIC2018**
track taxonomy. NSO E05/E07 snapshots for 2023–2024 are explicitly labelled
VSIC2018; VSIC2025 and its crosswalk are not applied retroactively.
VSIC divisions 16 and 31 form woodworking; 24, 25, and 28 form the
metalworking structural profile. These are division-level broad sector proxies,
not a claim that every furniture enterprise uses wood. Wholesale, retail, and
repair are excluded.
`schemas/vietnam_hs6_product_mapping.json` stores the 14 current product
mappings at HS6; edge banding is explicitly grouped under 846599.

`data/market/vietnam_foundation/manifest.json` records NSO national structure,
employment, size, and turnover extracts and Comtrade query parameters. Empty
or rate-limited 2024–2025 responses are recorded as `no_rows_returned` or
`failed`, never zero imports. The authenticated full endpoint requires a
subscription key. Monthly 2026 YTD probes are separate and are not treated as
a complete series.

`national_structural_profiles.json` remains national-only and matches NSO
activity labels for enterprise count, employment, size distribution, and
turnover. It does not infer province demand or create an industry-by-province
table. Current momentum now includes NSO E07.01 (national IIP by industry) and
E07.02 (province IIP), available through preliminary 2024; the current catalog
does not expose 2025–2026 in these tables. Returning enterprises were not found
in the machine-readable snapshot.

## Phase 3 province enrichment

`province_fdi_context.json` and `province_industrial_park_context.json` are
separate context artifacts. FDI uses FIA/Ministry of Finance reports and
normalizes legacy province names through the checked 63-to-34 crosswalk. Only
additive registered-capital totals may be combined; YoY percentages are kept
null when multiple legacy rows would need aggregation. The 2025 FIA report
publishes a ranked subset, so absent rows remain null. The 2026-07 report page
was retrieved but its provincial detail is in an attached workbook not present
in the page HTML; it remains unknown.

The industrial-park output has one official provincial extract (Hưng Yên) and
33 explicit missing records. That page supports operating-park count and total
area only; occupancy, leased land, service land, tenants, and investment stay
null. The InvestVietnam directory is a searchable list of individual zones,
not a validated 34-province aggregate, so no count or ratio is inferred from
it. Current KCN coverage is therefore 1/34 for count and total area, and 0/34
for the other requested fields.

Neither artifact feeds a score, product-demand field, or industry-by-province
mapping. Each row carries source name/URL, source geography, period, unit, raw
value, transformation method, retrieval time, confidence, and limitation.

## Phase 3B coverage gate

The FIA 2025 HTML remains a ranked subset (10 of 34 normalized units). The
2026-07 page exposes an XLS attachment through an ASP.NET postback; the
download response inspected during this phase was HTML rather than XLS, so no
OCR or guessed values were used and the period remains `UNKNOWN` by province.
The report's national manufacturing FDI cannot be converted into a province
breakdown.

The KCN artifact has one official provincial source (Hưng Yên) and 33 missing
records. `coverage_gate` keeps comparison disabled: count and total area are
1/34; operating count is 1/34; occupancy, tenants, and leased land are 0/34.
The sparse Hưng Yên evidence is retained independently and is not ranked.
