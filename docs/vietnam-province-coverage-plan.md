# Vietnam province coverage plan

Phase 1 locks the source and indicator contract for the 34 administrative units effective 2025-07-01. It does not refresh data or change the production UI.

## What is authoritative

The canonical units and the 63-to-34 crosswalk are the existing `vietnam_provinces_2025.json` and `vietnam_province_crosswalk.json`. Every observation keeps its source name, source code, geography basis and reference period. Historical 63-province records are not relabeled as current 34-province values.

NSO PX-Web is the backbone for province enterprise and industry tables. Current NSO reports can add current IIP or manufacturing momentum where a numeric province observation is actually published. FIA/MOF is supplementary investment context. Industrial-park figures require an official authority source and a verifiable period. OSM remains discovery evidence only.

## Missing-data rules

`null` means that the source did not provide a usable observation for that indicator and geography. It is displayed as **Unknown** with a reason. A zero is allowed only when the source explicitly observes zero. A national figure, a top-10 table, a directory omission or an old province value cannot be used to fill a current province.

Rates, shares, indices, growth and occupancy are never added across the historical crosswalk. Additive counts, areas or capital may be reaggregated only after checking complete component coverage, common definition and common period.

## Phase gates

1. Inspect source metadata and attachments before extraction.
2. Produce indicator-specific coverage reports with source period and geography.
3. Validate sample unchanged units and merged units separately.
4. Persist only complete refresh snapshots; keep the previous complete snapshot when a batch fails.
5. Enable province comparison for a field only when coverage and comparability are documented. No composite Province Potential Score is permitted in this workstream.

The machine-readable inventory and contract are in `schemas/vietnam_province_source_inventory.json` and `schemas/vietnam_province_indicator_contract.json`.
