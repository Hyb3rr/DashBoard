"""Batch refresh of evidence-only industrial demand snapshots."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping
from uuid import uuid4

from app.core.industrial_demand import load_matrix, normalize_evidence


MODEL_VERSION = "market-demand-v2"
MATRIX_PATH = Path(__file__).resolve().parents[2] / "schemas" / "product_industry_matrix.json"


def build_evidence_rows(matrix: Mapping[str, Any], inputs: Iterable[Mapping[str, Any]],
                        snapshot_id: str, collected_at: str) -> list[dict[str, Any]]:
    """Expand observed category signals to explicitly labelled product evidence."""
    products = matrix["products"]
    rows = []
    for item in inputs:
        track = item.get("track")
        category = "woodworking" if track == "woodworking" else "metalworking" if track == "metal_fabrication" else None
        if category is None:
            continue
        for product in products:
            if product["category"] != category:
                continue
            raw = {
                "snapshot_id": snapshot_id,
                "product_id": product["product_id"],
                "source_id": "osm_overpass",
                "source_geo_scope": "geo_unit",
                "geo_unit_id": item["geo_unit_id"],
                "country_code": item["country_code"],
                "observed_value": item.get("observed_value"),
                "unit": "weighted_mapped_establishments",
                "observed_period": item.get("source_snapshot_id") or "unknown",
                "collected_at": collected_at,
                "mapping_version": matrix["schema_version"],
                "limitations": [
                    "OSM entity coverage is partial",
                    "category-level proxy; not a factory census or purchase signal",
                    "raw value is comparable only within the same source track",
                    "city membership identifier is retained from the persisted OSM source mapping",
                ],
                "metadata": {"source_track": track, "processes": product["processes"],
                             "city_name": item.get("city_name")},
            }
            # The core identity includes snapshot_id, so the same observation
            # can be retained in successive historical snapshots.
            rows.append(normalize_evidence(raw))
    return rows


def refresh(repo: Any, country_code: str = "VN", now: datetime | None = None) -> dict[str, Any]:
    matrix = load_matrix(MATRIX_PATH)
    now = now or datetime.now(timezone.utc)
    collected_at = now.isoformat()
    snapshot_id = str(uuid4())
    inputs = repo.list_industrial_demand_inputs(country_code)
    rows = build_evidence_rows(matrix, inputs, snapshot_id, collected_at)
    repo.create_industrial_demand_snapshot({
        "snapshot_id": snapshot_id, "country_code": country_code.upper(),
        "model_version": MODEL_VERSION, "product_count": len(matrix["products"]),
        "evidence_count": len(rows),
    })
    try:
        repo.upsert_industrial_demand_evidence(rows)
        published = repo.publish_industrial_demand_snapshot(snapshot_id, len(rows))
    except Exception:
        # The old published snapshot remains visible; pending work is left for
        # inspection/retry rather than being reported as a successful refresh.
        raise
    return {"status": "published" if published else "not_published", "country": country_code.upper(),
            "snapshot_id": snapshot_id, "products": len(matrix["products"]), "evidence": len(rows)}
