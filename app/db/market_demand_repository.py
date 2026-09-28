"""Persistence for RFQ intake and published market-demand snapshots."""

from __future__ import annotations

import json
from typing import Any, Iterable

from .market_repository_utils import _executemany
from .postgres import transaction


_RFQ_UPSERT_SQL = """
    INSERT INTO rfq_intake
      (rfq_id,geo_unit_id,product_id,customer_name,customer_company,stage,quoted_at,
       deal_value_original,deal_value_currency,fx_rate_used,fx_rate_date,fx_rate_provider,won_at,lost_reason,
       is_repeat_customer,sales_rep,source_channel,source_system,source_record_id,created_at,notes)
    VALUES (COALESCE(%s::uuid,gen_random_uuid()),%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,COALESCE(%s::timestamptz,now()),%s)
    ON CONFLICT (source_system,source_record_id) WHERE source_record_id IS NOT NULL DO UPDATE SET
      geo_unit_id=EXCLUDED.geo_unit_id,product_id=EXCLUDED.product_id,customer_name=EXCLUDED.customer_name,
      customer_company=EXCLUDED.customer_company,stage=EXCLUDED.stage,quoted_at=EXCLUDED.quoted_at,
      deal_value_original=EXCLUDED.deal_value_original,deal_value_currency=EXCLUDED.deal_value_currency,
      fx_rate_used=EXCLUDED.fx_rate_used,fx_rate_date=EXCLUDED.fx_rate_date,
      fx_rate_provider=EXCLUDED.fx_rate_provider,won_at=EXCLUDED.won_at,
      lost_reason=EXCLUDED.lost_reason,is_repeat_customer=EXCLUDED.is_repeat_customer,
      sales_rep=EXCLUDED.sales_rep,source_channel=EXCLUDED.source_channel,notes=EXCLUDED.notes
"""


def _rfq_values(item: dict[str, Any]) -> tuple[Any, ...]:
    """Map one normalized RFQ record to the database column order."""
    return (
        item.get("rfq_id") or None, item["geo_unit_id"], item["product_id"], item["customer_name"],
        item.get("customer_company") or None, item["stage"], item.get("quoted_at") or None,
        item.get("deal_value_original") or None, item.get("deal_value_currency") or None,
        item.get("fx_rate_used") or None, item.get("fx_rate_date") or None,
        item.get("fx_rate_provider") or None, item.get("won_at") or None,
        item.get("lost_reason") or None, str(item.get("is_repeat_customer", "false")).lower() in {"1", "true", "yes"},
        item.get("sales_rep") or None, item.get("source_channel") or None,
        item.get("source_system") or "manual_csv", item.get("source_record_id") or None,
        item.get("created_at") or None, item.get("notes") or None,
    )


class MarketDemandRepositoryMixin:
    """Provide product-prior, industrial-demand, and country-demand persistence."""

    def upsert_rfq_intake(self, items: Iterable[dict[str, Any]]) -> int:
        """Persist normalized request-for-quote intake and processing state."""
        payload = list(items)
        if not payload:
            return 0
        values = [_rfq_values(item) for item in payload]
        with transaction() as conn:
            _executemany(conn, _RFQ_UPSERT_SQL, values)
        return len(payload)

    def list_product_tracks(self) -> list[dict[str, Any]]:
        """List configured product tracks and their source metadata."""
        with transaction() as conn:
            rows = conn.execute("SELECT product_id,category,hs_codes FROM product_track WHERE active IS TRUE ORDER BY product_id").fetchall()
        return [dict(row) for row in rows]

    def upsert_country_product_priors(self, items: Iterable[dict[str, Any]]) -> int:
        """Persist country-level priors for product demand."""
        payload = list(items)
        if not payload:
            return 0
        values = [(
            item.get("snapshot_id") or None, item["country_code"], item["product_id"], item.get("country_product_prior"),
            item.get("data_coverage", 0), item.get("source_quality"), json.dumps(item.get("signal_values") or {}),
            item.get("limitations") or [], json.dumps(item.get("source_updated_at") or {}),
            item["model_version"], item.get("calculated_at") or None,
        ) for item in payload]
        with transaction() as conn:
            _executemany(conn, """
                INSERT INTO market_country_product_prior
                  (snapshot_id,country_code,product_id,country_product_prior,data_coverage,source_quality,
                   signal_values,limitations,source_updated_at,model_version,calculated_at)
                VALUES (COALESCE(%s::uuid,gen_random_uuid()),%s,%s,%s,%s,%s,%s::jsonb,%s,%s::jsonb,%s,COALESCE(%s::timestamptz,now()))
            """, values)
        return len(values)

    def create_industrial_demand_snapshot(self, item: dict[str, Any]) -> str:
        """Create or reuse a pending snapshot; safe for job retries."""
        snapshot_id = str(item["snapshot_id"])
        with transaction() as conn:
            conn.execute("""
                INSERT INTO industrial_demand_snapshot
                  (snapshot_id,country_code,geo_scope,model_version,product_count,evidence_count)
                VALUES (%s::uuid,%s,%s,%s,%s,%s)
                ON CONFLICT (snapshot_id) DO NOTHING
            """, (snapshot_id, item["country_code"],
                  item.get("geo_scope", "confirmed_administrative_geo_unit"),
                  item["model_version"], int(item.get("product_count", 0)),
                  int(item.get("evidence_count", 0))))
        return snapshot_id

    def upsert_industrial_demand_evidence(self, items: Iterable[dict[str, Any]]) -> int:
        """Persist source-backed industrial demand observations."""
        payload = list(items)
        if not payload:
            return 0
        values = [(
            item["snapshot_id"], item["evidence_id"], item["country_code"], item.get("geo_unit_id"),
            item.get("product_id"), item["source_id"], item["source_geo_scope"],
            json.dumps(item.get("observed_value")) if item.get("observed_value") is not None else None,
            item.get("unit"), item["observed_period"], item["collected_at"], item["mapping_version"],
            json.dumps(item.get("limitations") or []), json.dumps(item.get("metadata") or {}),
        ) for item in payload]
        with transaction() as conn:
            _executemany(conn, """
                INSERT INTO industrial_demand_evidence
                  (snapshot_id,evidence_id,country_code,geo_unit_id,product_id,source_id,source_geo_scope,
                   observed_value,unit,observed_period,collected_at,mapping_version,limitations,metadata)
                VALUES (%s::uuid,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s::timestamptz,%s,%s::jsonb,%s::jsonb)
                ON CONFLICT (snapshot_id,evidence_id) DO UPDATE SET
                  observed_value=EXCLUDED.observed_value,unit=EXCLUDED.unit,
                  observed_period=EXCLUDED.observed_period,collected_at=EXCLUDED.collected_at,
                  mapping_version=EXCLUDED.mapping_version,limitations=EXCLUDED.limitations,
                  metadata=EXCLUDED.metadata
            """, values)
        return len(values)

    def publish_industrial_demand_snapshot(self, snapshot_id: str, evidence_count: int) -> bool:
        """Publish only after the producer has durably written the batch."""
        with transaction() as conn:
            result = conn.execute("""
                UPDATE industrial_demand_snapshot
                   SET status='published', evidence_count=%s, completed_at=now(), error_message=NULL
                 WHERE snapshot_id=%s::uuid AND status='pending'
            """, (int(evidence_count), snapshot_id))
        return getattr(result, "rowcount", 0) == 1

    def list_latest_industrial_demand_evidence(self, country_code: str, snapshot_id: str | None = None) -> list[dict[str, Any]]:
        """Load the latest industrial demand evidence by country."""
        with transaction() as conn:
            query = """
                SELECT e.*, s.model_version, s.completed_at AS snapshot_completed_at
                  FROM industrial_demand_evidence e
                  JOIN industrial_demand_snapshot s ON s.snapshot_id=e.snapshot_id
                 WHERE e.country_code=%s AND s.status='published'
            """
            params: list[Any] = [country_code.upper()]
            if snapshot_id:
                query += " AND e.snapshot_id=%s::uuid"
                params.append(snapshot_id)
            else:
                query += """ AND s.completed_at=(
                     SELECT MAX(completed_at) FROM industrial_demand_snapshot
                      WHERE country_code=%s AND status='published'
                   )"""
                params.append(country_code.upper())
            query += """
                 ORDER BY e.geo_unit_id NULLS FIRST, e.product_id NULLS FIRST, e.evidence_id
            """
            rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def get_latest_industrial_demand_snapshot(self, country_code: str) -> dict[str, Any] | None:
        """Return the latest published industrial demand snapshot."""
        with transaction() as conn:
            row = conn.execute("""
                SELECT * FROM industrial_demand_snapshot
                 WHERE country_code=%s AND status='published'
                 ORDER BY completed_at DESC NULLS LAST LIMIT 1
            """, (country_code.upper(),)).fetchone()
        return dict(row) if row else None

    def list_industrial_demand_inputs(self, country_code: str) -> list[dict[str, Any]]:
        """Read confirmed geo-unit OSM aggregates for the evidence refresh."""
        with transaction() as conn:
            rows = conn.execute("""
                SELECT m.city_id AS geo_unit_id, a.name AS city_name, m.country_code, f.track,
                       SUM((CASE WHEN f.track='woodworking'
                                 THEN f.furniture_evidence_count + f.wood_processing_count + f.sawmill_count
                                 ELSE f.metal_evidence_count END)
                           * COALESCE(m.membership_fraction, 0)) AS observed_value,
                       m.snapshot_id AS source_snapshot_id
                  FROM market_city_cell_membership m
                  JOIN market_areas a ON a.area_id=m.city_id
                  JOIN market_osm_snapshots s
                    ON s.snapshot_id=m.snapshot_id AND s.country_code=m.country_code
                   AND s.active AND s.status='active'
                  JOIN market_cell_features f
                    ON f.snapshot_id=m.snapshot_id AND f.country_code=m.country_code
                   AND f.h3_cell_id=m.h3_cell_id AND f.h3_resolution=m.h3_resolution
                 WHERE m.country_code=%s AND m.membership_status='ready'
                 GROUP BY m.snapshot_id, m.city_id, a.name, m.country_code, f.track
                 ORDER BY m.city_id, f.track
            """, (country_code.upper(),)).fetchall()
        return [dict(row) for row in rows]

    def create_country_demand_snapshot(self, snapshot_id: str, period: str, min_sample_threshold: int) -> dict[str, Any]:
        """Create a versioned country-demand snapshot record."""
        if period not in {"7d", "30d", "90d"}:
            raise ValueError("unsupported country demand period")
        with transaction() as conn:
            row = conn.execute("""
                INSERT INTO country_demand_snapshot(snapshot_id,period,min_sample_threshold,status)
                VALUES (%s::uuid,%s,%s,'pending')
                ON CONFLICT(snapshot_id) DO UPDATE SET
                  period=EXCLUDED.period,min_sample_threshold=EXCLUDED.min_sample_threshold,
                  status='pending',error_message=NULL,completed_at=NULL
                RETURNING *
            """, (snapshot_id, period, int(min_sample_threshold))).fetchone()
        return dict(row)

    def write_country_demand_signals(self, snapshot_id: str, countries: Iterable[dict[str, Any]]) -> int:
        """Persist computed country-demand signals for a snapshot."""
        payload = list(countries)
        values = [(
            snapshot_id, item["country_code"], json.dumps(item, ensure_ascii=False),
            int(item.get("qualified_sessions", 0)), item.get("signal", "INSUFFICIENT_DATA"),
            item.get("confidence", "—"),
        ) for item in payload]
        if not values:
            return 0
        with transaction() as conn:
            _executemany(conn, """
                INSERT INTO country_demand_signal
                  (snapshot_id,country_code,payload,qualified_sessions,signal,confidence)
                VALUES (%s::uuid,%s,%s::jsonb,%s,%s,%s)
                ON CONFLICT(snapshot_id,country_code) DO UPDATE SET
                  payload=EXCLUDED.payload,qualified_sessions=EXCLUDED.qualified_sessions,
                  signal=EXCLUDED.signal,confidence=EXCLUDED.confidence
            """, values)
        return len(values)

    def publish_country_demand_snapshot(self, snapshot_id: str, country_count: int) -> bool:
        """Publish a completed country-demand snapshot."""
        with transaction() as conn:
            result = conn.execute("""
                UPDATE country_demand_snapshot
                   SET status='published',country_count=%s,completed_at=now(),error_message=NULL
                 WHERE snapshot_id=%s::uuid AND status='pending'
            """, (int(country_count), snapshot_id))
        return getattr(result, "rowcount", 0) == 1

    def list_latest_country_demand_signals(self, period: str = "30d") -> dict[str, Any] | None:
        """Load country-demand signals from the latest published snapshot."""
        with transaction() as conn:
            snapshot = conn.execute("""
                SELECT * FROM country_demand_snapshot
                 WHERE period=%s AND status='published'
                 ORDER BY completed_at DESC NULLS LAST LIMIT 1
            """, (period,)).fetchone()
            if not snapshot:
                return None
            rows = conn.execute("""
                SELECT country_code,payload,qualified_sessions,signal,confidence
                  FROM country_demand_signal WHERE snapshot_id=%s::uuid
                 ORDER BY qualified_sessions DESC,country_code
            """, (str(snapshot["snapshot_id"]),)).fetchall()
        result = dict(snapshot)
        result["countries"] = [dict(row["payload"]) for row in rows]
        return result
