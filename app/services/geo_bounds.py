"""Cached coarse country bounds from the repository's GeoBoundaries data."""

from __future__ import annotations

from functools import lru_cache
import json
import os
from pathlib import Path
from typing import Any


def _pairs(value: Any):
    if isinstance(value, (list, tuple)):
        if len(value) >= 2 and all(isinstance(item, (int, float)) for item in value[:2]):
            yield float(value[1]), float(value[0])
        else:
            for child in value:
                yield from _pairs(child)


@lru_cache(maxsize=256)
def country_bounds(country_code: str) -> tuple[float, float, float, float] | None:
    """Return min_lat, min_lon, max_lat, max_lon for one ISO alpha-2 country."""
    root = Path(os.getenv("GEO_BOUNDARIES_DIR", "data/geography/geoboundaries"))
    matches = list(root.glob(f"{country_code.upper()}*/ADM1.json"))
    points = []
    for path in matches:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for feature in payload.get("features", []):
            points.extend(_pairs(feature.get("geometry", {}).get("coordinates", [])))
    if not points:
        return None
    lats, lons = zip(*points)
    return min(lats), min(lons), max(lats), max(lons)


def bounds_for(codes: set[str]) -> dict[str, tuple[float, float, float, float]]:
    return {code: bounds for code in codes if (bounds := country_bounds(code)) is not None}
