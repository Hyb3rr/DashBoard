"""Persistence boundary for the market-opportunity foundation."""

from __future__ import annotations

import json
from typing import Any, Iterable

from .postgres import transaction


AREA_TYPES = {"city", "administrative_area", "industrial_cluster"}
GRANULARITY_CLASSES = {"unknown", "normal", "coarse", "degenerate"}


def _rows(items: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    result = [dict(item) for item in items]
    keys = [item.get("country_code") for item in result]
    if any(not key for key in keys) or len(keys) != len(set(keys)):
        raise ValueError("catalog country_code values must be present and unique")
    return result


def _area_row(item: dict[str, Any]) -> tuple[Any, ...]:
    area_type = item.get("area_type")
    granularity = item.get("granularity_class", "unknown")
    if area_type not in AREA_TYPES:
        raise ValueError(f"unsupported market area type: {area_type}")
    if granularity not in GRANULARITY_CLASSES:
        raise ValueError(f"unsupported market granularity class: {granularity}")
    if not item.get("area_id") or not item.get("country_code") or not item.get("name"):
        raise ValueError("market area requires area_id, country_code and name")
    return (
        item["area_id"], item["country_code"], item["name"], area_type,
        item.get("admin_level"), granularity, item.get("parent_area_id"),
        item.get("source"), item.get("source_id"), item.get("centroid_lat"),
        item.get("centroid_lon"), item.get("bbox_min_lat"), item.get("bbox_min_lon"),
        item.get("bbox_max_lat"), item.get("bbox_max_lon"),
        json.dumps(item.get("geometry_ref") or {}), bool(item.get("active", True)),
    )


def _executemany(conn: Any, sql: str, values: list[tuple[Any, ...]]) -> None:
    """Use psycopg3's cursor batch API while keeping the transaction owned by caller."""
    with conn.cursor() as cursor:
        cursor.executemany(sql, values)


class MarketRepository:
    """Batch read/write access for market identity, provenance and job state."""

    def list_catalog(self, primary_market: bool | None = None, active: bool | None = None) -> list[dict[str, Any]]:
        clauses, params = [], []
        if primary_market is not None:
            clauses.append("primary_market = %s")
            params.append(primary_market)
        if active is not None:
            clauses.append("active = %s")
            params.append(active)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with transaction() as conn:
            rows = conn.execute(f"SELECT * FROM market_catalog{where} ORDER BY country_code", params).fetchall()
        return [dict(row) for row in rows]

    def upsert_catalog(self, items: Iterable[dict[str, Any]]) -> int:
        payload = _rows(items)
        if not payload:
            return 0
        values = [(
            item["country_code"], item["country_name"], item.get("iso3_code"),
            bool(item.get("un_member", False)), bool(item.get("primary_market", False)),
            bool(item.get("active", True)),
        ) for item in payload]
        with transaction() as conn:
            _executemany(conn, """
                INSERT INTO market_catalog
                  (country_code,country_name,iso3_code,un_member,primary_market,active)
                VALUES (%s,%s,%s,%s,%s,%s)
                ON CONFLICT(country_code) DO UPDATE SET
                  country_name=EXCLUDED.country_name,
                  iso3_code=EXCLUDED.iso3_code,
                  un_member=EXCLUDED.un_member,
                  primary_market=EXCLUDED.primary_market,
                  active=EXCLUDED.active,
                  updated_at=now()
            """, values)
        return len(payload)

    def list_areas(self, country_code: str | None = None, area_type: str | None = None) -> list[dict[str, Any]]:
        clauses, params = [], []
        if country_code:
            clauses.append("country_code = %s")
            params.append(country_code.upper())
        if area_type:
            if area_type not in AREA_TYPES:
                raise ValueError(f"unsupported market area type: {area_type}")
            clauses.append("area_type = %s")
            params.append(area_type)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with transaction() as conn:
            rows = conn.execute(f"SELECT * FROM market_areas{where} ORDER BY area_id", params).fetchall()
        return [dict(row) for row in rows]

    def upsert_areas(self, items: Iterable[dict[str, Any]]) -> int:
        payload = list(items)
        values = [_area_row(item) for item in payload]
        if not values:
            return 0
        with transaction() as conn:
            _executemany(conn, """
                INSERT INTO market_areas
                  (area_id,country_code,name,area_type,admin_level,granularity_class,parent_area_id,
                   source,source_id,centroid_lat,centroid_lon,bbox_min_lat,bbox_min_lon,bbox_max_lat,
                   bbox_max_lon,geometry_ref,active)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s)
                ON CONFLICT(area_id) DO UPDATE SET
                  country_code=EXCLUDED.country_code,name=EXCLUDED.name,area_type=EXCLUDED.area_type,
                  admin_level=EXCLUDED.admin_level,granularity_class=EXCLUDED.granularity_class,
                  parent_area_id=EXCLUDED.parent_area_id,source=EXCLUDED.source,source_id=EXCLUDED.source_id,
                  centroid_lat=EXCLUDED.centroid_lat,centroid_lon=EXCLUDED.centroid_lon,
                  bbox_min_lat=EXCLUDED.bbox_min_lat,bbox_min_lon=EXCLUDED.bbox_min_lon,
                  bbox_max_lat=EXCLUDED.bbox_max_lat,bbox_max_lon=EXCLUDED.bbox_max_lon,
                  geometry_ref=EXCLUDED.geometry_ref,active=EXCLUDED.active,updated_at=now()
            """, values)
        return len(values)

    def upsert_area_sources(self, items: Iterable[dict[str, Any]]) -> int:
        payload = list(items)
        values = [(
            item["area_id"], item["source_name"], item["source_object_id"], item.get("source_version"),
            item.get("source_confidence"), item.get("last_checked_at"), item.get("last_success_at"),
            json.dumps(item.get("metadata") or {}),
        ) for item in payload]
        if not values:
            return 0
        with transaction() as conn:
            _executemany(conn, """
                INSERT INTO market_area_sources
                  (area_id,source_name,source_object_id,source_version,source_confidence,
                   last_checked_at,last_success_at,metadata)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
                ON CONFLICT(area_id,source_name,source_object_id) DO UPDATE SET
                  source_version=EXCLUDED.source_version,source_confidence=EXCLUDED.source_confidence,
                  last_checked_at=EXCLUDED.last_checked_at,last_success_at=EXCLUDED.last_success_at,
                  metadata=EXCLUDED.metadata
            """, values)
        return len(values)

    def upsert_job_state(self, item: dict[str, Any]) -> dict[str, Any]:
        if not item.get("job_key") or not item.get("source"):
            raise ValueError("market job requires job_key and source")
        values = (
            item["job_key"], item["source"], item.get("country_code"), item.get("status", "pending"),
            item.get("current_step"), item.get("source_version"), item.get("source_hash"),
            int(item.get("retry_count", 0)), item.get("last_error"), item.get("started_at"),
            item.get("last_heartbeat_at"), item.get("completed_at"),
        )
        with transaction() as conn:
            row = conn.execute("""
                INSERT INTO market_job_state
                  (job_key,source,country_code,status,current_step,source_version,source_hash,retry_count,
                   last_error,started_at,last_heartbeat_at,completed_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(job_key) DO UPDATE SET
                  source=EXCLUDED.source,country_code=EXCLUDED.country_code,status=EXCLUDED.status,
                  current_step=EXCLUDED.current_step,source_version=EXCLUDED.source_version,
                  source_hash=EXCLUDED.source_hash,retry_count=EXCLUDED.retry_count,last_error=EXCLUDED.last_error,
                  started_at=EXCLUDED.started_at,last_heartbeat_at=EXCLUDED.last_heartbeat_at,
                  completed_at=EXCLUDED.completed_at,updated_at=now()
                RETURNING *
            """, values).fetchone()
        return dict(row)

    def get_job_state(self, job_key: str) -> dict[str, Any] | None:
        with transaction() as conn:
            row = conn.execute("SELECT * FROM market_job_state WHERE job_key=%s", (job_key,)).fetchone()
        return dict(row) if row else None

    def upsert_osm_snapshot(self, item: dict[str, Any]) -> dict[str, Any]:
        required = ("snapshot_id", "country_code", "source_url", "source_version", "source_hash",
                    "filter_version", "classification_version", "h3_resolution")
        if any(not item.get(key) and item.get(key) != 0 for key in required):
            raise ValueError("OSM snapshot metadata is incomplete")
        with transaction() as conn:
            row = conn.execute("""
                INSERT INTO market_osm_snapshots
                  (snapshot_id,country_code,source_url,source_version,source_hash,filter_version,
                   classification_version,h3_resolution,status,active)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,FALSE)
                ON CONFLICT(snapshot_id) DO UPDATE SET
                  source_url=EXCLUDED.source_url,source_version=EXCLUDED.source_version,
                  source_hash=EXCLUDED.source_hash,filter_version=EXCLUDED.filter_version,
                  classification_version=EXCLUDED.classification_version,
                  h3_resolution=EXCLUDED.h3_resolution,
                  status=CASE WHEN market_osm_snapshots.active THEN market_osm_snapshots.status ELSE EXCLUDED.status END
                RETURNING *
            """, (*[item[key] for key in required], item.get("status", "staging"))).fetchone()
        return dict(row)

    def upsert_cell_features(self, items: Iterable[dict[str, Any]]) -> int:
        payload = list(items)
        if not payload:
            return 0
        columns = ("snapshot_id", "country_code", "h3_cell_id", "h3_resolution", "track", "source",
                   "source_version", "classification_version", "industrial_area_count", "works_count",
                   "sawmill_count", "furniture_evidence_count", "wood_processing_count",
                   "metal_evidence_count", "machinery_evidence_count", "osm_feature_count",
                   "osm_last_observed", "osm_feature_density")
        values = [tuple(item.get(key, 0 if key.endswith("_count") else None) for key in columns) for item in payload]
        with transaction() as conn:
            _executemany(conn, """
                INSERT INTO market_cell_features
                  (snapshot_id,country_code,h3_cell_id,h3_resolution,track,source,source_version,
                   classification_version,industrial_area_count,works_count,sawmill_count,
                   furniture_evidence_count,wood_processing_count,metal_evidence_count,
                   machinery_evidence_count,osm_feature_count,osm_last_observed,osm_feature_density)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(snapshot_id,country_code,h3_cell_id,h3_resolution,track) DO UPDATE SET
                  industrial_area_count=EXCLUDED.industrial_area_count,works_count=EXCLUDED.works_count,
                  sawmill_count=EXCLUDED.sawmill_count,furniture_evidence_count=EXCLUDED.furniture_evidence_count,
                  wood_processing_count=EXCLUDED.wood_processing_count,metal_evidence_count=EXCLUDED.metal_evidence_count,
                  machinery_evidence_count=EXCLUDED.machinery_evidence_count,osm_feature_count=EXCLUDED.osm_feature_count,
                  osm_last_observed=EXCLUDED.osm_last_observed,osm_feature_density=EXCLUDED.osm_feature_density,
                  updated_at=now()
            """, values)
        return len(values)

    def upsert_opportunity_cells(self, items: Iterable[dict[str, Any]]) -> int:
        payload = list(items)
        if not payload:
            return 0
        values = [(
            item["snapshot_id"], item["country_code"], item["h3_cell_id"], item["h3_resolution"],
            item["track"], bool(item.get("active", True)), int(item.get("evidence_count", 0)),
            item.get("evidence_status", "observed"),
        ) for item in payload]
        with transaction() as conn:
            _executemany(conn, """
                INSERT INTO market_opportunity_cells
                  (snapshot_id,country_code,h3_cell_id,h3_resolution,track,active,evidence_count,evidence_status)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(snapshot_id,country_code,h3_cell_id,h3_resolution,track) DO UPDATE SET
                  active=EXCLUDED.active,evidence_count=EXCLUDED.evidence_count,
                  evidence_status=EXCLUDED.evidence_status,updated_at=now()
            """, values)
        return len(values)

    def upsert_auxiliary_evidence(self, items: Iterable[dict[str, Any]]) -> int:
        payload = list(items)
        if not payload:
            return 0
        columns = (
            "snapshot_id", "country_code", "h3_cell_id", "h3_resolution", "track", "source",
            "source_version", "source_hash", "industrial_land_count", "motorway_count",
            "primary_road_count", "railway_count", "port_count", "airport_count",
            "access_observation_count", "evidence_status",
        )
        values = [tuple(item.get(key, 0 if key.endswith("_count") else "observed" if key == "evidence_status" else None) for key in columns) for item in payload]
        with transaction() as conn:
            _executemany(conn, """
                INSERT INTO market_cell_auxiliary_evidence
                  (snapshot_id,country_code,h3_cell_id,h3_resolution,track,source,source_version,source_hash,
                   industrial_land_count,motorway_count,primary_road_count,railway_count,port_count,airport_count,
                   access_observation_count,evidence_status)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(snapshot_id,country_code,h3_cell_id,h3_resolution,track) DO UPDATE SET
                  source=EXCLUDED.source,source_version=EXCLUDED.source_version,source_hash=EXCLUDED.source_hash,
                  industrial_land_count=EXCLUDED.industrial_land_count,motorway_count=EXCLUDED.motorway_count,
                  primary_road_count=EXCLUDED.primary_road_count,railway_count=EXCLUDED.railway_count,
                  port_count=EXCLUDED.port_count,airport_count=EXCLUDED.airport_count,
                  access_observation_count=EXCLUDED.access_observation_count,evidence_status=EXCLUDED.evidence_status,
                  updated_at=now()
            """, values)
        return len(values)

    def upsert_local_opportunity(self, items: Iterable[dict[str, Any]]) -> int:
        payload = list(items)
        if not payload:
            return 0
        values = [(
            item["snapshot_id"], item["country_code"], item.get("area_id"), item["h3_cell_id"],
            item["h3_resolution"], item["track"], item.get("raw_local_score"),
            item["evidence_status"], json.dumps(item.get("evidence_components") or {}),
            json.dumps(item.get("coverage_fields") or {}), item["model_version"], item.get("missing_reason"),
        ) for item in payload]
        with transaction() as conn:
            _executemany(conn, """
                INSERT INTO market_local_opportunity
                  (snapshot_id,country_code,area_id,h3_cell_id,h3_resolution,track,raw_local_score,
                   evidence_status,evidence_components,coverage_fields,model_version,missing_reason)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb,%s,%s)
                ON CONFLICT(snapshot_id,country_code,h3_cell_id,h3_resolution,track) DO UPDATE SET
                  area_id=EXCLUDED.area_id,raw_local_score=EXCLUDED.raw_local_score,
                  evidence_status=EXCLUDED.evidence_status,evidence_components=EXCLUDED.evidence_components,
                  coverage_fields=EXCLUDED.coverage_fields,model_version=EXCLUDED.model_version,
                  missing_reason=EXCLUDED.missing_reason,updated_at=now()
            """, values)
        return len(values)

    def activate_osm_snapshot(self, country_code: str, snapshot_id: str) -> dict[str, Any]:
        """Atomically supersede old country snapshot and activate new one."""
        with transaction() as conn:
            row = conn.execute("""
                SELECT * FROM market_osm_snapshots
                WHERE snapshot_id=%s AND country_code=%s AND status IN ('staging', 'active')
                FOR UPDATE
            """, (snapshot_id, country_code.upper())).fetchone()
            if not row:
                raise ValueError("OSM snapshot is not staging for this country")
            if row["status"] == "active" and row["active"]:
                return dict(row)
            conn.execute("""
                UPDATE market_osm_snapshots SET active=FALSE,status='superseded'
                WHERE country_code=%s AND active
            """, (country_code.upper(),))
            activated = conn.execute("""
                UPDATE market_osm_snapshots SET active=TRUE,status='active',activated_at=now()
                WHERE snapshot_id=%s RETURNING *
            """, (snapshot_id,)).fetchone()
        return dict(activated)

    def active_osm_snapshot(self, country_code: str) -> dict[str, Any] | None:
        with transaction() as conn:
            row = conn.execute("""
                SELECT * FROM market_osm_snapshots WHERE country_code=%s AND active
            """, (country_code.upper(),)).fetchone()
        return dict(row) if row else None

    def country_product_demand(self, country_code: str) -> float | None:
        with transaction() as conn:
            row = conn.execute("""
                SELECT economic_indicators->'market_components'->>'product_demand' AS demand
                FROM region_profiles WHERE country_code=%s
            """, (country_code.upper(),)).fetchone()
        try:
            return float(row["demand"]) if row and row["demand"] is not None else None
        except (TypeError, ValueError):
            return None

    def list_active_local_inputs(self, country_code: str) -> list[dict[str, Any]]:
        with transaction() as conn:
            rows = conn.execute("""
                SELECT f.snapshot_id,f.country_code,f.h3_cell_id,f.h3_resolution,f.track,
                       f.osm_feature_count,f.industrial_area_count,
                       COALESCE(a.industrial_land_count,0) AS industrial_land_count,
                       COALESCE(a.access_observation_count,0) AS access_observation_count
                FROM market_cell_features f
                JOIN market_osm_snapshots s ON s.snapshot_id=f.snapshot_id
                  AND s.country_code=f.country_code AND s.active
                LEFT JOIN market_cell_auxiliary_evidence a
                  ON a.snapshot_id=f.snapshot_id AND a.country_code=f.country_code
                 AND a.h3_cell_id=f.h3_cell_id AND a.h3_resolution=f.h3_resolution AND a.track=f.track
                WHERE f.country_code=%s
                ORDER BY f.h3_cell_id,f.track
            """, (country_code.upper(),)).fetchall()
        return [dict(row) for row in rows]

    def list_active_area_summary_inputs(self, country_code: str) -> list[dict[str, Any]]:
        """Read active local-opportunity rows for the area-summary worker.

        This is deliberately a read-only projection.  Unmapped cells retain a
        NULL area_id and are returned so the worker can report them without
        inventing an area membership.
        """
        with transaction() as conn:
            rows = conn.execute("""
                SELECT l.snapshot_id,l.country_code,l.area_id,l.h3_cell_id,
                       l.h3_resolution,l.track,l.raw_local_score,l.evidence_status,
                       l.model_version,l.calibration_version
                FROM market_local_opportunity l
                JOIN market_osm_snapshots s ON s.snapshot_id=l.snapshot_id
                  AND s.country_code=l.country_code AND s.active
                WHERE l.country_code=%s
                ORDER BY l.snapshot_id,l.area_id,l.track,l.h3_cell_id
            """, (country_code.upper(),)).fetchall()
        return [dict(row) for row in rows]

    def list_raw_local_scores(self) -> list[dict[str, Any]]:
        with transaction() as conn:
            rows = conn.execute("""
                SELECT l.country_code,l.track,l.raw_local_score,a.area_type
                FROM market_local_opportunity l
                LEFT JOIN market_areas a ON a.area_id=l.area_id
                WHERE l.evidence_status='scored' AND l.raw_local_score IS NOT NULL
            """).fetchall()
        return [dict(row) for row in rows]

    def list_calibration_candidates(self) -> list[dict[str, Any]]:
        with transaction() as conn:
            rows = conn.execute("""
                SELECT l.snapshot_id,l.country_code,l.h3_cell_id,l.h3_resolution,l.track,
                       l.raw_local_score,a.area_type
                FROM market_local_opportunity l
                JOIN market_areas a ON a.area_id=l.area_id
                WHERE l.evidence_status='scored' AND l.raw_local_score IS NOT NULL
                  AND a.area_type='administrative_area'
                ORDER BY l.track,l.country_code,l.h3_cell_id
            """).fetchall()
        return [dict(row) for row in rows]

    def update_local_calibration(self, items: Iterable[dict[str, Any]]) -> int:
        payload = list(items)
        if not payload:
            return 0
        with transaction() as conn:
            _executemany(conn, """
                UPDATE market_local_opportunity
                SET calibrated_score=%s, peer_percentile=%s, calibration_method=%s,
                    calibration_version=%s, calibration_status=%s, updated_at=now()
                WHERE snapshot_id=%s AND country_code=%s AND h3_cell_id=%s
                  AND h3_resolution=%s AND track=%s
            """, [(
                item.get("calibrated_score"), item.get("peer_percentile"),
                item.get("calibration_method"), item.get("calibration_version"),
                item["calibration_status"], item["snapshot_id"], item["country_code"],
                item["h3_cell_id"], item["h3_resolution"], item["track"],
            ) for item in payload])
        return len(payload)

    def upsert_area_overlap(self, items: Iterable[dict[str, Any]]) -> int:
        payload = list(items)
        if not payload:
            return 0
        with transaction() as conn:
            _executemany(conn, """
                INSERT INTO market_area_overlap
                  (snapshot_id,country_code,h3_resolution,track,area_id_a,area_id_b,
                   shared_opportunity,opportunity_a,opportunity_b,overlap_a_to_b,overlap_b_to_a,
                   remaining_opportunity_a,remaining_opportunity_b,calculation_version)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(snapshot_id,country_code,h3_resolution,track,area_id_a,area_id_b)
                DO UPDATE SET shared_opportunity=EXCLUDED.shared_opportunity,
                  opportunity_a=EXCLUDED.opportunity_a,opportunity_b=EXCLUDED.opportunity_b,
                  overlap_a_to_b=EXCLUDED.overlap_a_to_b,overlap_b_to_a=EXCLUDED.overlap_b_to_a,
                  remaining_opportunity_a=EXCLUDED.remaining_opportunity_a,
                  remaining_opportunity_b=EXCLUDED.remaining_opportunity_b,
                  calculation_version=EXCLUDED.calculation_version,updated_at=now()
            """, [(
                item["snapshot_id"], item["country_code"], item["h3_resolution"], item["track"],
                item["area_id_a"], item["area_id_b"], item.get("shared_opportunity", 0),
                item.get("opportunity_a", 0), item.get("opportunity_b", 0), item.get("overlap_a_to_b", 0),
                item.get("overlap_b_to_a", 0), item.get("remaining_opportunity_a", 0),
                item.get("remaining_opportunity_b", 0), item["calculation_version"],
            ) for item in payload])
        return len(payload)

    def list_calibrated_cells_for_overlap(self, country_code: str) -> list[dict[str, Any]]:
        with transaction() as conn:
            rows = conn.execute("""
                WITH RECURSIVE memberships AS (
                  SELECT l.snapshot_id,l.country_code,l.h3_cell_id,l.h3_resolution,l.track,
                         l.calibrated_score,l.calibration_version,l.area_id
                  FROM market_local_opportunity l
                  JOIN market_osm_snapshots s ON s.snapshot_id=l.snapshot_id
                    AND s.country_code=l.country_code AND s.active
                  WHERE l.country_code=%s AND l.calibration_status='selected'
                    AND l.calibrated_score IS NOT NULL AND l.area_id IS NOT NULL
                  UNION ALL
                  SELECT m.snapshot_id,m.country_code,m.h3_cell_id,m.h3_resolution,m.track,
                         m.calibrated_score,m.calibration_version,a.parent_area_id
                  FROM memberships m JOIN market_areas a ON a.area_id=m.area_id
                  WHERE a.parent_area_id IS NOT NULL
                ) SELECT * FROM memberships
            """, (country_code.upper(),)).fetchall()
        return [dict(row) for row in rows]

    def replace_area_overlap(self, country_code: str, snapshot_id: str, track: str,
                             h3_resolution: int, items: Iterable[dict[str, Any]]) -> int:
        payload = list(items)
        with transaction() as conn:
            conn.execute("DELETE FROM market_area_overlap WHERE country_code=%s AND snapshot_id=%s AND track=%s AND h3_resolution=%s",
                         (country_code.upper(), snapshot_id, track, h3_resolution))
            if payload:
                _executemany(conn, """
                    INSERT INTO market_area_overlap
                      (snapshot_id,country_code,h3_resolution,track,area_id_a,area_id_b,
                       shared_opportunity,opportunity_a,opportunity_b,overlap_a_to_b,overlap_b_to_a,
                       remaining_opportunity_a,remaining_opportunity_b,calculation_version)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, [(
                    item["snapshot_id"],item["country_code"],item["h3_resolution"],item["track"],
                    item["area_id_a"],item["area_id_b"],item["shared_opportunity"],item["opportunity_a"],
                    item["opportunity_b"],item["overlap_a_to_b"],item["overlap_b_to_a"],
                    item["remaining_opportunity_a"],item["remaining_opportunity_b"],item["calculation_version"]
                ) for item in payload])
        return len(payload)

    def list_local_opportunities_for_api(self, country_code: str) -> list[dict[str, Any]]:
        with transaction() as conn:
            rows = conn.execute("""
                SELECT l.country_code,l.snapshot_id,l.area_id,a.name AS area_name,a.area_type,
                       l.h3_cell_id,l.h3_resolution,l.track,l.raw_local_score,
                       l.calibrated_score,l.peer_percentile,l.evidence_status,l.missing_reason,
                       l.calibration_method,l.calibration_version,l.calibration_status
                FROM market_local_opportunity l
                LEFT JOIN market_areas a ON a.area_id=l.area_id
                JOIN market_osm_snapshots s ON s.snapshot_id=l.snapshot_id
                  AND s.country_code=l.country_code AND s.active
                WHERE l.country_code=%s
                ORDER BY l.track,l.calibrated_score DESC NULLS LAST,l.h3_cell_id
            """, (country_code.upper(),)).fetchall()
        return [dict(row) for row in rows]

    def upsert_area_opportunity_summaries(self, items: Iterable[dict[str, Any]]) -> int:
        payload = list(items)
        values = [(
            item["snapshot_id"], item["country_code"], item["h3_resolution"], item["area_id"],
            item["track"], item.get("total_cells", 0), item.get("scored_cells", 0),
            item.get("evidence_coverage", 0), item.get("area_raw_score"),
            item.get("area_calibrated_score"), item.get("area_percentile"),
            item.get("evidence_status", "pending"), item.get("missing_reason"),
            item["model_version"], item.get("calibration_version"),
        ) for item in payload]
        if not values:
            return 0
        with transaction() as conn:
            _executemany(conn, """
                INSERT INTO market_area_opportunity_summary
                  (snapshot_id,country_code,h3_resolution,area_id,track,total_cells,scored_cells,
                   evidence_coverage,area_raw_score,area_calibrated_score,area_percentile,
                   evidence_status,missing_reason,model_version,calibration_version)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (snapshot_id,country_code,h3_resolution,area_id,track) DO UPDATE SET
                  total_cells=EXCLUDED.total_cells,scored_cells=EXCLUDED.scored_cells,
                  evidence_coverage=EXCLUDED.evidence_coverage,area_raw_score=EXCLUDED.area_raw_score,
                  area_calibrated_score=EXCLUDED.area_calibrated_score,area_percentile=EXCLUDED.area_percentile,
                  evidence_status=EXCLUDED.evidence_status,missing_reason=EXCLUDED.missing_reason,
                  model_version=EXCLUDED.model_version,calibration_version=EXCLUDED.calibration_version,
                  updated_at=now()
            """, values)
        return len(values)

    def list_area_summaries_for_calibration(self) -> list[dict[str, Any]]:
        with transaction() as conn:
            rows = conn.execute("""
                SELECT o.snapshot_id,o.country_code,o.h3_resolution,o.area_id,o.track,
                       o.area_raw_score,o.area_calibrated_score,o.area_percentile,
                       o.evidence_status,o.model_version,a.area_type
                FROM market_area_opportunity_summary o
                JOIN market_areas a ON a.area_id=o.area_id
                WHERE o.area_raw_score IS NOT NULL AND o.evidence_status='scored'
                ORDER BY o.track,a.area_type,o.area_id
            """).fetchall()
        return [dict(row) for row in rows]

    def update_area_calibration(self, items: Iterable[dict[str, Any]]) -> int:
        payload = list(items)
        if not payload:
            return 0
        with transaction() as conn:
            _executemany(conn, """
                UPDATE market_area_opportunity_summary
                SET area_calibrated_score=%s,area_percentile=%s,
                    calibration_version=%s,updated_at=now()
                WHERE snapshot_id=%s AND country_code=%s AND h3_resolution=%s
                  AND area_id=%s AND track=%s
            """, [(item["area_calibrated_score"], item["area_percentile"], item["calibration_version"],
                    item["snapshot_id"],item["country_code"],item["h3_resolution"],item["area_id"],item["track"]) for item in payload])
        return len(payload)

    def list_area_opportunity_summaries(self, country_code: str, track: str | None = None) -> list[dict[str, Any]]:
        clauses = ["s.country_code=%s", "s.active"]
        params: list[Any] = [country_code.upper()]
        if track:
            if track not in {"woodworking", "metal_fabrication"}:
                raise ValueError(f"unsupported market track: {track}")
            clauses.append("o.track=%s")
            params.append(track)
        with transaction() as conn:
            rows = conn.execute(f"""
                SELECT o.*,a.name AS area_name,a.area_type
                FROM market_area_opportunity_summary o
                JOIN market_osm_snapshots s ON s.snapshot_id=o.snapshot_id
                  AND s.country_code=o.country_code
                JOIN market_areas a ON a.area_id=o.area_id
                WHERE {' AND '.join(clauses)}
                ORDER BY o.track,o.area_raw_score DESC NULLS LAST,a.name
            """, params).fetchall()
        return [dict(row) for row in rows]

    def list_city_opportunity_summaries(self, country_code: str, track: str | None = None) -> list[dict[str, Any]]:
        clauses = ["s.country_code=%s", "s.active"]
        params: list[Any] = [country_code.upper()]
        if track:
            if track not in {"woodworking", "metal_fabrication"}:
                raise ValueError(f"unsupported market track: {track}")
            clauses.append("o.track=%s")
            params.append(track)
        with transaction() as conn:
            rows = conn.execute(f"""
                SELECT o.*,a.name AS city_name,a.area_type
                FROM market_city_opportunity_summary o
                JOIN market_osm_snapshots s ON s.snapshot_id=o.snapshot_id
                  AND s.country_code=o.country_code
                JOIN market_areas a ON a.area_id=o.city_id
                WHERE {' AND '.join(clauses)}
                ORDER BY o.track,o.city_calibrated_score DESC NULLS LAST,a.name
            """, params).fetchall()
        return [dict(row) for row in rows]

    def upsert_city_cell_memberships(self, items: Iterable[dict[str, Any]]) -> int:
        payload = list(items)
        if not payload:
            return 0
        with transaction() as conn:
            _executemany(conn, """
                INSERT INTO market_city_cell_membership
                  (snapshot_id,country_code,city_id,h3_cell_id,h3_resolution,intersection_area,
                   membership_fraction,geometry_source,geometry_version,membership_status,model_version)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (snapshot_id,country_code,city_id,h3_cell_id,h3_resolution) DO UPDATE SET
                  intersection_area=EXCLUDED.intersection_area,membership_fraction=EXCLUDED.membership_fraction,
                  geometry_source=EXCLUDED.geometry_source,geometry_version=EXCLUDED.geometry_version,
                  membership_status=EXCLUDED.membership_status,model_version=EXCLUDED.model_version,updated_at=now()
            """, [(
                item["snapshot_id"],item["country_code"],item["city_id"],item["h3_cell_id"],item["h3_resolution"],
                item.get("intersection_area"),item.get("membership_fraction"),item["geometry_source"],
                item["geometry_version"],item.get("membership_status", "ready"),item["model_version"]
            ) for item in payload])
        return len(payload)

    def list_city_registry(self, country_code: str) -> list[dict[str, Any]]:
        with transaction() as conn:
            rows = conn.execute("""
                SELECT source_id,name,area_id FROM market_areas
                WHERE country_code=%s AND area_type='city' AND source='ghsl' AND active
                ORDER BY source_id
            """, (country_code.upper(),)).fetchall()
        return [dict(row) for row in rows]

    def upsert_city_opportunity_summaries(self, items: Iterable[dict[str, Any]]) -> int:
        payload = list(items)
        if not payload:
            return 0
        with transaction() as conn:
            _executemany(conn, """
                INSERT INTO market_city_opportunity_summary
                  (snapshot_id,country_code,city_id,track,total_cells,scored_cells,membership_weight,
                   scored_membership_weight,evidence_coverage,city_raw_score,city_calibrated_score,
                   city_percentile,evidence_status,missing_reason,geometry_source,model_version,calibration_version)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (snapshot_id,country_code,city_id,track) DO UPDATE SET
                  total_cells=EXCLUDED.total_cells,scored_cells=EXCLUDED.scored_cells,
                  membership_weight=EXCLUDED.membership_weight,scored_membership_weight=EXCLUDED.scored_membership_weight,
                  evidence_coverage=EXCLUDED.evidence_coverage,city_raw_score=EXCLUDED.city_raw_score,
                  city_calibrated_score=EXCLUDED.city_calibrated_score,city_percentile=EXCLUDED.city_percentile,
                  evidence_status=EXCLUDED.evidence_status,missing_reason=EXCLUDED.missing_reason,
                  geometry_source=EXCLUDED.geometry_source,model_version=EXCLUDED.model_version,
                  calibration_version=EXCLUDED.calibration_version,updated_at=now()
            """, [(
                item["snapshot_id"],item["country_code"],item["city_id"],item["track"],item.get("total_cells",0),item.get("scored_cells",0),
                item.get("membership_weight",0),item.get("scored_membership_weight",0),item.get("evidence_coverage",0),item.get("city_raw_score"),
                item.get("city_calibrated_score"),item.get("city_percentile"),item.get("evidence_status","pending"),item.get("missing_reason"),
                item["geometry_source"],item["model_version"],item.get("calibration_version")
            ) for item in payload])
        return len(payload)

    def list_city_summary_inputs(self, countries: Iterable[str] | None = None) -> list[dict[str, Any]]:
        selected = [str(code).strip().upper() for code in (countries or []) if str(code).strip()]
        clauses = ["m.membership_status='ready'"]
        params: list[Any] = []
        if selected:
            clauses.append("m.country_code = ANY(%s)")
            params.append(selected)
        with transaction() as conn:
            rows = conn.execute(f"""
                SELECT m.snapshot_id,m.country_code,m.city_id,m.h3_cell_id,m.h3_resolution,
                       m.membership_fraction,m.geometry_source,m.geometry_version,
                       l.track,l.raw_local_score,l.evidence_status,l.model_version
                FROM market_city_cell_membership m
                JOIN market_local_opportunity l
                  ON l.snapshot_id=m.snapshot_id AND l.country_code=m.country_code
                 AND l.h3_cell_id=m.h3_cell_id AND l.h3_resolution=m.h3_resolution
                WHERE {' AND '.join(clauses)}
                ORDER BY m.country_code,m.city_id,m.h3_cell_id
            """, params).fetchall()
        return [dict(row) for row in rows]

    def list_active_h3_cells(self, country_code: str) -> list[dict[str, Any]]:
        with transaction() as conn:
            rows = conn.execute("""
                SELECT DISTINCT l.snapshot_id,l.country_code,l.h3_cell_id,l.h3_resolution
                FROM market_local_opportunity l
                JOIN market_osm_snapshots s ON s.snapshot_id=l.snapshot_id
                  AND s.country_code=l.country_code AND s.active
                WHERE l.country_code=%s ORDER BY l.h3_cell_id
            """, (country_code.upper(),)).fetchall()
        return [dict(row) for row in rows]

    def list_area_overlap_for_api(self, country_code: str) -> list[dict[str, Any]]:
        with transaction() as conn:
            rows = conn.execute("""
                SELECT o.*,a.name AS area_name_a,b.name AS area_name_b
                FROM market_area_overlap o
                JOIN market_areas a ON a.area_id=o.area_id_a
                JOIN market_areas b ON b.area_id=o.area_id_b
                JOIN market_osm_snapshots s ON s.snapshot_id=o.snapshot_id
                  AND s.country_code=o.country_code AND s.active
                WHERE o.country_code=%s
                ORDER BY o.track,o.overlap_a_to_b DESC,o.area_id_a,o.area_id_b
            """, (country_code.upper(),)).fetchall()
        return [dict(row) for row in rows]

    def country_iso3(self, country_code: str) -> str | None:
        with transaction() as conn:
            row = conn.execute("SELECT iso3_code FROM market_catalog WHERE country_code=%s", (country_code.upper(),)).fetchone()
        return row["iso3_code"] if row else None

    def administrative_levels(self, country_code: str) -> set[int]:
        """Return the adaptive boundary levels actually present in the read model."""
        with transaction() as conn:
            rows = conn.execute("""
                SELECT DISTINCT admin_level
                FROM market_areas
                WHERE country_code=%s AND area_type='administrative_area'
                  AND admin_level IS NOT NULL
            """, (country_code.upper(),)).fetchall()
        return {int(row["admin_level"]) for row in rows}

    def list_local_cells_for_mapping(self, country_code: str) -> list[dict[str, Any]]:
        with transaction() as conn:
            rows = conn.execute("""
                SELECT DISTINCT l.snapshot_id,l.country_code,l.h3_cell_id,l.h3_resolution
                FROM market_local_opportunity l
                JOIN market_osm_snapshots s ON s.snapshot_id=l.snapshot_id
                 AND s.country_code=l.country_code AND s.active
                LEFT JOIN market_areas existing_area ON existing_area.area_id=l.area_id
                WHERE l.country_code=%s AND (l.area_id IS NULL OR existing_area.area_id IS NULL)
            """, (country_code.upper(),)).fetchall()
        return [dict(row) for row in rows]

    def update_local_area_membership(self, items: Iterable[dict[str, Any]]) -> int:
        payload = list(items)
        if not payload:
            return 0
        with transaction() as conn:
            _executemany(conn, """
                UPDATE market_local_opportunity
                SET area_id=%s, updated_at=now()
                WHERE snapshot_id=%s AND country_code=%s AND h3_cell_id=%s AND h3_resolution=%s
            """, [(item["area_id"], item["snapshot_id"], item["country_code"], item["h3_cell_id"], item["h3_resolution"]) for item in payload])
        return len(payload)
