# Repository layout

The repository keeps application source and deployable configuration at the
root, while local runtime artifacts are grouped separately.

```text
app/                         FastAPI, collector, detection, enrichment
scripts/                     Operations, migrations, refresh and benchmarks
tests/                       Unit, integration and browser-contract tests
rules/                       Detection rule definitions
schemas/                     Data contracts and market/geo schemas
infra/                       PostgreSQL and ClickHouse configuration
docs/                        Architecture, reviews and operational documentation
.ai/                         Project state, plans and decisions

runtime/                     Local generated artifacts; never application source
runtime/artifacts/           UUIDs and ClickHouse artifacts from local runs
data/                        Local databases, raw archive and provider datasets
tools/manual/                Manual browser/client test pages
attachments/reference/       Local reference documents and research attachments
```

`data/` and `runtime/` are local runtime areas and must not be treated as
source-controlled application state. The active ClickHouse data directory is
`data/clickhouse/`, configured by `infra/clickhouse/config.xml`.
