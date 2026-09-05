"""External market source registry.

This module contains source metadata only. Processing policy remains in the
OSM/H3 worker and does not branch on individual countries.
"""

from __future__ import annotations

import os
from typing import Final


WAVE_1_COUNTRIES: Final[tuple[str, ...]] = (
    "IN", "CH", "SA", "IE", "BR", "ES", "CA", "FR", "JP", "AU",
    "NL", "MX", "CZ", "SE", "BE", "PT", "RO", "AT", "DK", "NZ",
)

PRIORITY_SOURCE_URLS: Final[dict[str, str]] = {
    "SG": "https://download.geofabrik.de/asia/malaysia-singapore-brunei-latest.osm.pbf",
    "VN": "https://download.geofabrik.de/asia/vietnam-latest.osm.pbf",
    "DE": "https://download.geofabrik.de/europe/germany/berlin-latest.osm.pbf",
    "TH": "https://download.geofabrik.de/asia/thailand-latest.osm.pbf",
    "MY": "https://download.geofabrik.de/asia/malaysia-singapore-brunei-latest.osm.pbf",
    "ID": "https://download.geofabrik.de/asia/indonesia-latest.osm.pbf",
    "PH": "https://download.geofabrik.de/asia/philippines-latest.osm.pbf",
    "KR": "https://download.geofabrik.de/asia/south-korea-latest.osm.pbf",
    "PL": "https://download.geofabrik.de/europe/poland-latest.osm.pbf",
    "IT": "https://download.geofabrik.de/europe/italy-latest.osm.pbf",
}

WAVE_1_SOURCE_URLS: Final[dict[str, str]] = {
    "IN": "https://download.geofabrik.de/asia/india-latest.osm.pbf",
    "CH": "https://download.geofabrik.de/europe/switzerland-latest.osm.pbf",
    "IE": "https://download.geofabrik.de/europe/ireland-and-northern-ireland-latest.osm.pbf",
    "BR": "https://download.geofabrik.de/south-america/brazil-latest.osm.pbf",
    "ES": "https://download.geofabrik.de/europe/spain-latest.osm.pbf",
    "CA": "https://download.geofabrik.de/north-america/canada-latest.osm.pbf",
    "FR": "https://download.geofabrik.de/europe/france-latest.osm.pbf",
    "JP": "https://download.geofabrik.de/asia/japan-latest.osm.pbf",
    "AU": "https://download.geofabrik.de/australia-oceania/australia-latest.osm.pbf",
    "NL": "https://download.geofabrik.de/europe/netherlands-latest.osm.pbf",
    "MX": "https://download.geofabrik.de/north-america/mexico-latest.osm.pbf",
    "CZ": "https://download.geofabrik.de/europe/czech-republic-latest.osm.pbf",
    "SE": "https://download.geofabrik.de/europe/sweden-latest.osm.pbf",
    "BE": "https://download.geofabrik.de/europe/belgium-latest.osm.pbf",
    "PT": "https://download.geofabrik.de/europe/portugal-latest.osm.pbf",
    "RO": "https://download.geofabrik.de/europe/romania-latest.osm.pbf",
    "AT": "https://download.geofabrik.de/europe/austria-latest.osm.pbf",
    "DK": "https://download.geofabrik.de/europe/denmark-latest.osm.pbf",
    "NZ": "https://download.geofabrik.de/australia-oceania/new-zealand-latest.osm.pbf",
}

# Expansion sources stay explicit and country-scoped. Regional extracts are
# never selected as an accidental substitute for a country source.
EXPANSION_SOURCE_URLS: Final[dict[str, str]] = {
    "AD": "https://download.geofabrik.de/europe/andorra-latest.osm.pbf",
    "AF": "https://download.geofabrik.de/asia/afghanistan-latest.osm.pbf",
    "AL": "https://download.geofabrik.de/europe/albania-latest.osm.pbf",
}

# Geofabrik currently exposes Saudi Arabia only through a multi-country GCC
# extract. Do not use that file as a country snapshot because it would mix
# countries before a country-boundary filter exists.
UNSUPPORTED_OSM_COUNTRIES: Final[dict[str, str]] = {
    "SA": "no country-scoped OSM PBF source; regional GCC extract is not country-safe",
}

OSM_SOURCE_URLS: Final[dict[str, str]] = {
    **PRIORITY_SOURCE_URLS,
    **WAVE_1_SOURCE_URLS,
    **EXPANSION_SOURCE_URLS,
}
SUPPORTED_OSM_COUNTRIES: Final[tuple[str, ...]] = tuple(OSM_SOURCE_URLS)


def resolve_osm_source(country_code: str, env: dict[str, str] | None = None) -> tuple[str, str]:
    """Resolve a registered country to an explicit URL and source kind."""
    country = str(country_code).strip().upper()
    if country in UNSUPPORTED_OSM_COUNTRIES:
        raise ValueError(f"OSM source explicitly unsupported for {country}: {UNSUPPORTED_OSM_COUNTRIES[country]}")
    if country not in OSM_SOURCE_URLS:
        raise ValueError(f"OSM source is not registered for country: {country}")
    environment = env if env is not None else os.environ
    override = str(environment.get(f"OSM_URL_{country}", "")).strip()
    return (override, "environment_override") if override else (OSM_SOURCE_URLS[country], "geofabrik_registry")
