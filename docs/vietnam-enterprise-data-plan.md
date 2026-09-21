# Vietnam enterprise evidence

This phase adds a batch-only registry-derived evidence source for the 34
current Vietnam administrative units. It does not create a Province Potential
Score or allocate national data to provinces.

## Source contract

The collector uses the public Doanhnghiep.vn v1 API. The API currently exposes
province reference data and company-list totals filtered by province, activity
prefix and active status. It is treated as a third-party registry proxy, not as
an NSO statistic or an official factory registry.

The source documentation advertises a 60-request/minute/IP limit and a 24-hour
cache requirement. The collector therefore runs as an explicit scheduled batch,
keeps the source URL and retrieval time, and never calls the API from a request
handler.

## Working taxonomy

The API returned manufacturing prefixes in the form `C16`, `C31`, `C24`,
`C25`, and `C28`. The snapshot preserves these raw codes. They are mapped to
the project's VSIC2018 working taxonomy as follows:

| Track | API prefixes | Interpretation |
| --- | --- | --- |
| woodworking | C16, C31 | wood products plus broad furniture proxy |
| metalworking | C24, C25, C28 | basic metals, fabricated metal, machinery |

The API documentation does not state the underlying VSIC revision. Until that
is independently verified, the mapping remains `VSIC2018-working-1`; it must not
be described as an official VSIC2018 extract.

## What is stored

For each current province and track, the snapshot stores the aggregate only when
every target prefix returned a numeric `total`. Each component keeps its raw API
prefix, URL, raw value, reference label and limitation. A real zero is retained;
a failed request, missing province or malformed response becomes `null`.

The first indicator is `target_enterprise_count` in active registered
enterprises. `target_enterprise_density` is deliberately deferred until a
same-period population or total-enterprise denominator is selected. No score or
purchase probability is produced.

## Validation gate

Before exposing this evidence in the production province profile:

1. compare totals against NSO enterprise tables where definitions overlap;
2. check duplicate MST behavior by sampling paginated records;
3. verify that all 34 API province names map exactly to the current catalogue;
4. confirm the API's underlying industry revision and code labels;
5. publish only a complete snapshot, keeping the last complete snapshot on
   rate-limit or source failure.
