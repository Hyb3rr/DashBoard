"""Seed reviewable public city candidates from GeoNames and Country Prior."""
from __future__ import annotations

import csv
import io
import json
import os
import urllib.request
import zipfile
from collections import defaultdict
from typing import Any, Iterable

from dotenv import load_dotenv

load_dotenv()

from app.db.postgres import transaction

GEONAMES_URL = os.getenv(
    "GEONAMES_CITIES_URL",
    "https://download.geonames.org/export/dump/cities5000.zip",
)
MAX_COUNTRIES = 15
PER_COUNTRY = 2
CANDIDATE_MODE = os.getenv("GEO_CANDIDATE_MODE", "vn").lower()
PRIORITY_COUNTRY = os.getenv("GEO_CANDIDATE_PRIORITY_COUNTRY", "VN").upper()
PRIORITY_CITY_LIMIT = int(os.getenv("GEO_CANDIDATE_PRIORITY_CITY_LIMIT", "30"))


def parse_geonames(payload: bytes) -> list[dict[str, Any]]:
    """Parse the public GeoNames tab file without inventing business fields."""
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        names = [name for name in archive.namelist() if name.endswith(".txt")]
        if not names:
            raise ValueError("GeoNames archive has no tabular city file")
        raw = archive.read(names[0]).decode("utf-8")
    rows = []
    for fields in csv.reader(io.StringIO(raw), delimiter="\t"):
        feature_code = fields[7] if len(fields) > 7 else ""
        is_city = feature_code == "PPL" or feature_code == "PPLC" or feature_code.startswith("PPLA")
        if len(fields) < 15 or fields[6] != "P" or not is_city:
            continue
        try:
            latitude, longitude, population = float(fields[4]), float(fields[5]), int(fields[14])
        except (TypeError, ValueError):
            continue
        if not fields[8] or not fields[1] or population <= 0:
            continue
        rows.append({
            "geoname_id": fields[0], "country_code": fields[8].upper(),
            "display_name": fields[1], "lat": latitude, "lng": longitude,
            "population": population,
        })
    return rows


def select_candidates(cities: Iterable[dict[str, Any]], ranked_countries: Iterable[str],
                      max_countries: int = MAX_COUNTRIES,
                      per_country: int = PER_COUNTRY) -> list[dict[str, Any]]:
    """Select largest public cities in high-prior countries, deterministically."""
    by_country: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for city in cities:
        by_country[city["country_code"]].append(city)
    selected = []
    for country in list(ranked_countries)[:max_countries]:
        cities_for_country = sorted(
            by_country.get(country, []),
            key=lambda item: (-item["population"], item["display_name"], item["geoname_id"]),
        )
        selected.extend(cities_for_country[:per_country])
    return selected


def _ranked_countries() -> list[str]:
    """Order countries by their latest coverage-adjusted product prior."""
    with transaction() as conn:
        rows = conn.execute(
            """
            SELECT country_code, MAX(country_product_prior) AS score,
                   AVG(data_coverage) AS coverage
            FROM (
              SELECT DISTINCT ON (country_code, product_id)
                     country_code, product_id, country_product_prior, data_coverage
              FROM market_country_product_prior
              ORDER BY country_code, product_id, calculated_at DESC
            ) latest
            WHERE country_product_prior IS NOT NULL
            GROUP BY country_code
            ORDER BY MAX(country_product_prior) * AVG(data_coverage) DESC, country_code
            """
        ).fetchall()
    return [row["country_code"] for row in rows]


def seed_candidates(fetcher=urllib.request.urlopen, url: str = GEONAMES_URL) -> dict[str, Any]:
    """Refresh reviewable city candidates from the public GeoNames dataset."""
    countries = _ranked_countries()
    if CANDIDATE_MODE == "global":
        selected_countries = countries[:MAX_COUNTRIES]
        per_country = PER_COUNTRY
    else:
        selected_countries = [PRIORITY_COUNTRY]
        per_country = PRIORITY_CITY_LIMIT
    if not selected_countries or any(country not in countries for country in selected_countries):
        return {"status": "blocked", "reason": "country_prior_unavailable", "inserted": 0}
    with fetcher(url, timeout=60) as response:
        cities = parse_geonames(response.read())
    selected = select_candidates(cities, selected_countries, max_countries=len(selected_countries), per_country=per_country)
    values = []
    for city in selected:
        values.append((
            f"{city['country_code']}-GN-{city['geoname_id']}", city["country_code"],
            "admin_city", city["display_name"], city["lat"], city["lng"],
            city["population"], json.dumps({"type": "point", "coordinates": [city["lng"], city["lat"]]}),
            "public_candidate; source=GeoNames cities5000; sales confirmation required",
        ))
    with transaction() as conn:
        retired = conn.execute(
            """
            UPDATE geo_unit
            SET status = 'retired', active = FALSE, updated_at = now()
            WHERE status = 'public_candidate'
              AND notes LIKE 'public_candidate; source=GeoNames cities5000%'
            """
        ).rowcount
        for value in values:
            conn.execute(
                """
                INSERT INTO geo_unit
                  (geo_unit_id,country_code,unit_type,display_name,lat,lng,population,
                   bounding_geometry,notes,status,active)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,'public_candidate',TRUE)
                ON CONFLICT (geo_unit_id) DO UPDATE SET
                  display_name=EXCLUDED.display_name, lat=EXCLUDED.lat, lng=EXCLUDED.lng,
                  population=EXCLUDED.population, bounding_geometry=EXCLUDED.bounding_geometry,
                  notes=EXCLUDED.notes, status='public_candidate', active=TRUE, updated_at=now()
                WHERE geo_unit.status IN ('public_candidate', 'retired')
                """,
                value,
            )
    return {"status": "updated", "source": "GeoNames cities5000", "mode": CANDIDATE_MODE,
            "countries_considered": len(selected_countries),
            "candidates": len(selected), "inserted": len(values), "retired_previous": retired,
            "country_order": selected_countries}


if __name__ == "__main__":
    print(json.dumps(seed_candidates(), indent=2))
