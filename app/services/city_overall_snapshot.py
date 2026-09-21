"""Build/publish boundary for the authoritative province/city opportunity read model."""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from ..core.city_overall_opportunity import score_rows
from .province_profile import build_vietnam_province_profile

MODEL_VERSION = "city-overall-v1"
PEER_GROUP = "VN-34"


def build_vietnam_snapshot(*, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    rows = build_vietnam_province_profile(include_overall=False).get("provinces", [])
    scores = score_rows(rows)
    return {"snapshot_id": str(uuid4()), "country_code": "VN", "peer_group": PEER_GROUP,
            "model_version": MODEL_VERSION, "calculated_at": now.isoformat(),
            "rows": [{"country_code": "VN", "geo_unit_id": row["geo_unit_id"],
                      "score": scores[row["geo_unit_id"]]["score"],
                      "evidence_coverage": scores[row["geo_unit_id"]]["evidence_coverage"],
                      "components": scores[row["geo_unit_id"]]["components"],
                      "limitations": scores[row["geo_unit_id"]]["missing_groups"],
                      "calculated_at": now.isoformat()} for row in rows]}


def publish_vietnam_snapshot(repository, *, now: datetime | None = None) -> dict:
    snapshot = build_vietnam_snapshot(now=now)
    repository.create_city_overall_snapshot(snapshot)
    repository.write_city_overall_rows(snapshot["rows"], snapshot["snapshot_id"])
    if not repository.publish_city_overall_snapshot(snapshot["snapshot_id"], "VN"):
        raise RuntimeError("city overall snapshot was not published")
    return {"status": "published", "snapshot_id": snapshot["snapshot_id"], "rows": len(snapshot["rows"]), "model_version": MODEL_VERSION}
