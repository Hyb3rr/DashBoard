"""Persistence boundary for the market-opportunity foundation."""

from __future__ import annotations

import json
from typing import Any, Iterable

from .market_demand_repository import MarketDemandRepositoryMixin
from .market_evidence_repository import MarketEvidenceRepositoryMixin
from .market_repository_utils import _executemany
from .postgres import transaction


AREA_TYPES = {"city", "administrative_area", "industrial_cluster"}
GRANULARITY_CLASSES = {"unknown", "normal", "coarse", "degenerate"}


def _rows(items: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert database rows into plain dictionaries."""
    result = [dict(item) for item in items]
    keys = [item.get("country_code") for item in result]
    if any(not key for key in keys) or len(keys) != len(set(keys)):
        raise ValueError("catalog country_code values must be present and unique")
    return result


def _area_row(item: dict[str, Any]) -> tuple[Any, ...]:
    """Normalize one administrative area for repository persistence."""
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


class MarketRepository(MarketEvidenceRepositoryMixin, MarketDemandRepositoryMixin):
    """Batch read/write access for market identity, provenance and job state."""

    def create_city_overall_snapshot(self, item: dict[str, Any]) -> str:
        """Create a versioned publication record for a city-overall score snapshot."""
        with transaction() as conn:
            conn.execute("""INSERT INTO city_overall_opportunity_snapshot
                (snapshot_id,country_code,peer_group,model_version,calculated_at,status)
                VALUES (%s,%s,%s,%s,%s,'staging')
                ON CONFLICT (snapshot_id) DO NOTHING""",
                         (item["snapshot_id"], item["country_code"], item["peer_group"],
                          item["model_version"], item["calculated_at"]))
        return str(item["snapshot_id"])

    def write_city_overall_rows(self, rows: Iterable[dict[str, Any]], snapshot_id: str) -> int:
        """Persist scored canonical province rows into a snapshot."""
        payload = list(rows)
        if not payload:
            return 0
        with transaction() as conn:
            _executemany(conn, """INSERT INTO city_overall_opportunity
                (snapshot_id,country_code,geo_unit_id,score,evidence_coverage,components,limitations,calculated_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (snapshot_id,geo_unit_id) DO UPDATE SET
                  score=EXCLUDED.score,evidence_coverage=EXCLUDED.evidence_coverage,
                  components=EXCLUDED.components,limitations=EXCLUDED.limitations,
                  calculated_at=EXCLUDED.calculated_at""",
                [(snapshot_id, row["country_code"], row["geo_unit_id"], row.get("score"),
                  row.get("evidence_coverage", 0), json.dumps(row.get("components") or {}),
                  json.dumps(row.get("limitations") or []), row.get("calculated_at")) for row in payload])
        return len(payload)

    def publish_city_overall_snapshot(self, snapshot_id: str, country_code: str) -> bool:
        """Mark a completed city-overall snapshot as the latest publication."""
        with transaction() as conn:
            conn.execute("UPDATE city_overall_opportunity_snapshot SET status='superseded' WHERE country_code=%s AND status='published'", (country_code.upper(),))
            row = conn.execute("""UPDATE city_overall_opportunity_snapshot
                SET status='published',published_at=now() WHERE snapshot_id=%s AND country_code=%s
                RETURNING snapshot_id""", (snapshot_id, country_code.upper())).fetchone()
        return bool(row)

    def latest_city_overall_snapshot(self, country_code: str) -> dict[str, Any] | None:
        """Load the most recently published city-overall snapshot."""
        with transaction() as conn:
            snapshot = conn.execute("""SELECT * FROM city_overall_opportunity_snapshot
                WHERE country_code=%s AND status='published' ORDER BY published_at DESC LIMIT 1""", (country_code.upper(),)).fetchone()
            if not snapshot:
                return None
            rows = conn.execute("""SELECT * FROM city_overall_opportunity
                WHERE snapshot_id=%s ORDER BY geo_unit_id""", (snapshot["snapshot_id"],)).fetchall()
        return {**dict(snapshot), "rows": [dict(row) for row in rows]}

    def list_catalog(self, primary_market: bool | None = None, active: bool | None = None) -> list[dict[str, Any]]:
        """List normalized product and geography catalog entries."""
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

    def list_page_classification_rules(self, active: bool = True) -> list[dict[str, Any]]:
        """List page-classification rules for a country."""
        with transaction() as conn:
            rows = conn.execute(
                "SELECT * FROM page_classification_rules WHERE active=%s ORDER BY priority DESC, id ASC",
                (bool(active),),
            ).fetchall()
        return [dict(row) for row in rows]

    def upsert_page_classification_rules(self, items: Iterable[dict[str, Any]]) -> int:
        """Replace persisted page-classification rules for a country."""
        payload = list(items)
        values = []
        for item in payload:
            if not item.get("pattern") or item.get("page_type") not in {"product", "content", "other"}:
                raise ValueError("page classification rule requires pattern and valid page_type")
            values.append((item["pattern"], item["page_type"], int(item.get("priority", 0)), bool(item.get("active", True))))
        if not values:
            return 0
        with transaction() as conn:
            _executemany(conn, """
                INSERT INTO page_classification_rules(pattern,page_type,priority,active)
                VALUES (%s,%s,%s,%s)
            """, values)
        return len(values)

    def upsert_catalog(self, items: Iterable[dict[str, Any]]) -> int:
        """Upsert normalized catalog entries from a source refresh."""
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
        """List administrative areas with their current source metadata."""
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
        """Upsert normalized administrative areas."""
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
        """Persist provenance and freshness for area-level source data."""
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
        """Record the latest status and outcome of a market-data job."""
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
        """Load the persisted status for one market-data job."""
        with transaction() as conn:
            row = conn.execute("SELECT * FROM market_job_state WHERE job_key=%s", (job_key,)).fetchone()
        return dict(row) if row else None

    def upsert_market_potential_summaries(self, items: Iterable[dict[str, Any]]) -> int:
        """Persist ranked market-potential summaries."""
        payload = list(items)
        if not payload:
            return 0
        values = [(
            item.get("snapshot_id"), item["geo_unit_id"], item["country_code"], item["product_id"],
            item.get("score"), item.get("score_type"), item.get("confidence"), item.get("data_coverage"),
            item.get("country_product_prior"), item.get("city_fit"), item.get("sales_validation_score"),
            item.get("w_internal"), item.get("w_city"), item.get("w_country"), item.get("competition_presence"),
            item.get("competition_strength"), item.get("market_validation"), item.get("white_space_score"),
            item.get("rfq_count_12m"), item.get("win_rate"), item.get("top_positive_reasons") or [],
            item.get("top_negative_reasons") or [], item.get("limitations") or [], item.get("calculated_at"),
        ) for item in payload]
        with transaction() as conn:
            _executemany(conn, """
                INSERT INTO market_city_product_summary
                  (snapshot_id,geo_unit_id,country_code,product_id,score,score_type,confidence,data_coverage,
                   country_product_prior,city_fit,sales_validation_score,w_internal,w_city,w_country,
                   competition_presence,competition_strength,market_validation,white_space_score,rfq_count_12m,
                   win_rate,top_positive_reasons,top_negative_reasons,limitations,calculated_at)
                VALUES (COALESCE(%s::uuid,gen_random_uuid()),%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,COALESCE(%s::timestamptz,now()))
            """, values)
        return len(values)

    def list_market_potential_summary_rows(self, geo_unit_id: str | None = None,
                                           product_id: str | None = None) -> list[dict[str, Any]]:
        """Load market-potential rows for API projection."""
        clauses, params = [], []
        if geo_unit_id:
            clauses.append("geo_unit_id=%s")
            params.append(geo_unit_id)
        if product_id:
            clauses.append("product_id=%s")
            params.append(product_id)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with transaction() as conn:
            rows = conn.execute(
                f"SELECT * FROM market_city_product_summary{where} ORDER BY score DESC NULLS LAST, geo_unit_id, product_id, calculated_at DESC",
                params,
            ).fetchall()
        return [dict(row) for row in rows]

    def list_market_identity_keys(self) -> tuple[set[str], set[str]]:
        """List stable identity keys used by market read models."""
        with transaction() as conn:
            geo = conn.execute(
                "SELECT geo_unit_id FROM geo_unit WHERE active IS TRUE AND status = 'confirmed'"
            ).fetchall()
            products = conn.execute("SELECT product_id FROM product_track").fetchall()
        return ({row["geo_unit_id"] for row in geo}, {row["product_id"] for row in products})
