"""Bounded local GeoNames hierarchy lookup.

This module is deliberately not an IP geolocation provider.  It only resolves
explicit GeoNames IDs and aliases through a versioned local index.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class GeoNamesHierarchy:
    def __init__(self, payload: dict[str, Any]):
        """Index GeoNames places and case-insensitive aliases from a payload."""
        self.version = str(payload.get("version") or "unknown")
        self._places = {str(item["id"]): item for item in payload.get("places", []) if item.get("id")}
        self._aliases = {
            str(alias).casefold(): ([str(place_id)] if isinstance(place_id, str)
                                    else [str(item) for item in place_id])
            for alias, place_id in (payload.get("aliases") or {}).items()
        }

    @classmethod
    def from_path(cls, path: str | Path) -> "GeoNamesHierarchy":
        """Load a versioned GeoNames hierarchy JSON file from disk."""
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def resolve(self, name: str, *, country_code: str | None = None,
                parent_ids: set[str] | None = None) -> dict[str, Any] | None:
        """Resolve an alias only when country and parent filters leave one place."""
        candidate_ids = list(self._aliases.get(str(name).strip().casefold()) or [])
        if country_code:
            candidate_ids = [place_id for place_id in candidate_ids
                             if str(self._places.get(place_id, {}).get("country_code", "")).upper() == country_code.upper()]
        if parent_ids:
            parent_ids = {str(item) for item in parent_ids}
            candidate_ids = [place_id for place_id in candidate_ids
                             if parent_ids.intersection({str(item) for item in self._places.get(place_id, {}).get("parents", [])})]
        if len(candidate_ids) != 1:
            return None
        place = self._places.get(candidate_ids[0])
        if not place:
            return None
        return dict(place)

    def parents(self, place_id: str) -> list[dict[str, Any]]:
        """Return known parent records for a GeoNames place identifier."""
        place = self._places.get(str(place_id))
        if not place:
            return []
        return [dict(self._places[parent]) for parent in place.get("parents", []) if parent in self._places]

    def canonical_city_parent(self, place: dict[str, Any]) -> dict[str, Any] | None:
        """Return a unique city/admin1 parent, without inferring from distance."""
        parents = [parent for parent in self.parents(str(place.get("id")))
                   if parent.get("kind") in {"city", "admin1"}]
        return parents[0] if len(parents) == 1 else None
