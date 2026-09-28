"""Build the product-level country/city blend for confirmed geo units."""
from __future__ import annotations

import json
import math
import uuid
from datetime import datetime, timezone
from typing import Any

from dotenv import load_dotenv

load_dotenv()

from app.core.market_potential import blend_scores, sales_validation_score, weighted_normalized_score
from app.db.market_repository import MarketRepository
from app.db.postgres import transaction

MODEL_VERSION = "market-potential-v1"
MAX_CITY_MATCH_KM = 75.0


def _distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Return the great-circle distance between two latitude/longitude pairs."""
    radius = 6371.0088
    first, second = math.radians(lat1), math.radians(lat2)
    d_lat, d_lon = math.radians(lat2 - lat1), math.radians(lon2 - lon1)
    value = math.sin(d_lat / 2) ** 2 + math.cos(first) * math.cos(second) * math.sin(d_lon / 2) ** 2
    return 2 * radius * math.asin(math.sqrt(value))


def nearest_city_fit(geo_unit: dict[str, Any], city_rows: list[dict[str, Any]], track: str) -> tuple[float | None, str | None, float | None]:
    """Find the nearest scored city for a geo unit within the configured radius."""
    candidates = [row for row in city_rows if row["track"] == track and row.get("city_calibrated_score") is not None]
    if geo_unit.get("lat") is None or geo_unit.get("lng") is None or not candidates:
        return None, None, None
    ranked = sorted(
        (
            _distance_km(float(geo_unit["lat"]), float(geo_unit["lng"]), float(row["centroid_lat"]), float(row["centroid_lon"])),
            row,
        )
        for row in candidates
        if row.get("centroid_lat") is not None and row.get("centroid_lon") is not None
    )
    if not ranked or ranked[0][0] > MAX_CITY_MATCH_KM:
        return None, None, None
    distance, row = ranked[0]
    return float(row["city_calibrated_score"]), row["city_id"], round(distance, 3)


def normalize_competition(values: dict[str, float]) -> dict[str, float]:
    """Scale competition evidence to a comparable 0–100 range."""
    if not values:
        return {}
    low, high = min(values.values()), max(values.values())
    if low == high:
        return {key: 50.0 for key in values}
    return {key: round((value - low) / (high - low) * 100, 4) for key, value in values.items()}


def _minmax(values: dict[Any, float | None]) -> dict[Any, float | None]:
    """Normalize optional values while preserving missing entries."""
    present = [value for value in values.values() if value is not None]
    if not present:
        return {key: None for key in values}
    low, high = min(present), max(present)
    if low == high:
        return {key: (None if value is None else 1.0) for key, value in values.items()}
    return {key: (None if value is None else (value - low) / (high - low)) for key, value in values.items()}


def build_sales_validation(rows: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    """Build RFQ scores from the SQL view, without inventing missing sales evidence."""
    by_product: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if int(row.get("rfq_count_12m") or 0) > 0:
            by_product.setdefault(row["product_id"], []).append(row)
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for product_id, group in by_product.items():
        count_norm = _minmax({id(row): math.log1p(int(row["rfq_count_12m"])) for row in group})
        deal_norm = _minmax({id(row): (float(row["avg_deal_value_usd"]) if row.get("avg_deal_value_usd") is not None else None) for row in group})
        signals_by_key = {}
        for row in group:
            count = int(row["rfq_count_12m"])
            signals_by_key[(row["geo_unit_id"], product_id)] = {
                "rfq_count": count_norm[id(row)],
                "quotation_response_rate": (float(row["quoted_count"]) / count) if count else None,
                "win_rate": row.get("win_rate"),
                "avg_deal_value": deal_norm[id(row)],
                "repeat_purchase": (1.0 if row.get("has_repeat_customer") else 0.0),
            }
        raw_values = {
            key: weighted_normalized_score(signals, {"rfq_count": 0.25, "quotation_response_rate": 0.20,
                                                     "win_rate": 0.25, "avg_deal_value": 0.20,
                                                     "repeat_purchase": 0.10})
            for key, signals in signals_by_key.items()
        }
        peers = [value / 100.0 for value in raw_values.values() if value is not None]
        for row in group:
            key = (row["geo_unit_id"], product_id)
            result[key] = {
                "score": sales_validation_score(signals_by_key[key], peers),
                "rfq_count_12m": int(row["rfq_count_12m"]),
                "win_rate": float(row["win_rate"]) if row.get("win_rate") is not None else None,
            }
    return result


def _load_refresh_inputs(country_code: str) -> dict[str, list[dict[str, Any]]]:
    """Load confirmed geography, priors, city fit, RFQ, and competition evidence."""
    with transaction() as conn:
        geo_units = [dict(row) for row in conn.execute(
            """SELECT geo_unit_id,country_code,lat,lng FROM geo_unit
               WHERE active IS TRUE AND status='confirmed' AND country_code=%s ORDER BY geo_unit_id""",
            (country_code.upper(),),
        ).fetchall()]
        priors = [dict(row) for row in conn.execute(
            """SELECT DISTINCT ON (country_code,product_id)
                      country_code,product_id,country_product_prior,data_coverage,signal_values
               FROM market_country_product_prior
               WHERE country_code=%s ORDER BY country_code,product_id,calculated_at DESC""",
            (country_code.upper(),),
        ).fetchall()]
        city_rows = [dict(row) for row in conn.execute(
            """SELECT s.city_id,s.track,s.city_calibrated_score,a.centroid_lat,a.centroid_lon
               FROM market_city_opportunity_summary s
               JOIN market_areas a ON a.area_id=s.city_id
               WHERE s.country_code=%s AND s.evidence_status='scored' AND a.active""",
            (country_code.upper(),),
        ).fetchall()]
        rfq_rows = [dict(row) for row in conn.execute(
            """SELECT geo_unit_id,product_id,rfq_count_12m,quoted_count,win_rate,
                      avg_deal_value_usd,has_repeat_customer
               FROM rfq_summary_by_geo_product"""
        ).fetchall()]
        competition_rows = [dict(row) for row in conn.execute(
            """SELECT m.city_id, f.track,
                      SUM(CASE WHEN f.track='woodworking'
                               THEN f.furniture_evidence_count + f.wood_processing_count + f.sawmill_count
                               ELSE f.metal_evidence_count + f.machinery_evidence_count END
                          * COALESCE(m.membership_fraction, 0)) AS evidence_count
               FROM market_city_cell_membership m
               JOIN market_cell_features f
                 ON f.snapshot_id=m.snapshot_id AND f.country_code=m.country_code
                AND f.h3_cell_id=m.h3_cell_id AND f.h3_resolution=m.h3_resolution
               WHERE m.country_code=%s AND m.membership_status='ready'
               GROUP BY m.city_id, f.track""",
            (country_code.upper(),),
        ).fetchall()]
    return {"geo_units": geo_units, "priors": priors, "city_rows": city_rows,
            "rfq_rows": rfq_rows, "competition_rows": competition_rows}


def _competition_by_track(rows: list[dict[str, Any]]) -> dict[str, dict[str, dict[str, float]]]:
    """Index raw and normalized competition evidence by industry track."""
    result = {}
    for track in ("woodworking", "metal_fabrication"):
        raw = {row["city_id"]: float(row["evidence_count"] or 0) for row in rows if row["track"] == track}
        result[track] = {"raw": raw, "normalized": normalize_competition(raw)}
    return result


def _build_summary_row(geo: dict, product: dict, prior: dict, city_rows: list[dict],
                       competition: dict, sales_by_key: dict, snapshot_id: str,
                       calculated_at: str) -> tuple[dict[str, Any], bool]:
    """Build one product-by-geo score row and report whether city evidence matched."""
    track = "woodworking" if product["category"] == "woodworking" else "metal_fabrication"
    city_fit, city_id, distance = nearest_city_fit(geo, city_rows, track)
    competition_presence = competition["raw"].get(city_id) if city_id else None
    competition_strength = competition["normalized"].get(city_id) if city_id else None
    country_prior = prior.get("country_product_prior")
    sales = sales_by_key.get((geo["geo_unit_id"], product["product_id"]), {})
    sales_score = sales.get("score")
    result = blend_scores(
        float(country_prior) if country_prior is not None else None,
        float(city_fit) if city_fit is not None else None,
        float(sales_score) if sales_score is not None else None,
        int(sales.get("rfq_count_12m") or 0),
    )
    limitations = []
    if city_fit is None:
        limitations.append("city_fit unavailable within match radius")
    if competition_strength is None:
        limitations.append("competition unavailable in partial OSM coverage")
        market_validation, white_space = "insufficient_evidence", None
    else:
        white_space = round(100.0 - competition_strength, 4)
        market_validation = (
            "possibly_saturated" if competition_strength >= 75 else
            "white_space" if competition_strength <= 25 else "validated_market"
        )
    if sales_score is None:
        limitations.append("sales validation unavailable without RFQ evidence")
    row = {
        "snapshot_id": snapshot_id,
        "geo_unit_id": geo["geo_unit_id"],
        "country_code": geo["country_code"],
        "product_id": product["product_id"],
        "score": result["score"],
        "score_type": result["score_type"],
        "confidence": 80.0 if sales_score is not None else (60.0 if city_fit is not None else 40.0),
        "data_coverage": float(prior.get("data_coverage") or 0),
        "country_product_prior": float(country_prior) if country_prior is not None else None,
        "city_fit": city_fit,
        "sales_validation_score": sales_score,
        "w_internal": result["weights"]["internal"],
        "w_city": result["weights"]["city"],
        "w_country": result["weights"]["country"],
        "competition_presence": competition_presence,
        "competition_strength": competition_strength,
        "market_validation": market_validation,
        "white_space_score": white_space,
        "rfq_count_12m": int(sales.get("rfq_count_12m") or 0),
        "win_rate": sales.get("win_rate"),
        "top_positive_reasons": ([f"city_fit_source={city_id}", f"city_match_km={distance}"] if city_id else []),
        "top_negative_reasons": [],
        "limitations": limitations,
        "calculated_at": calculated_at,
    }
    return row, city_fit is not None


def _build_summary_rows(geo_units: list[dict], products: list[dict], prior_by_product: dict,
                        city_rows: list[dict], competition_by_track: dict, sales_by_key: dict,
                        snapshot_id: str, calculated_at: str) -> tuple[list[dict[str, Any]], int]:
    """Build all product/geography rows and count city-fit matches."""
    rows, matched = [], 0
    for geo in geo_units:
        for product in products:
            track = "woodworking" if product["category"] == "woodworking" else "metal_fabrication"
            row, has_city_match = _build_summary_row(
                geo, product, prior_by_product.get(product["product_id"], {}), city_rows,
                competition_by_track[track], sales_by_key, snapshot_id, calculated_at,
            )
            rows.append(row)
            matched += has_city_match
    return rows, matched


def refresh(repo: MarketRepository | None = None, country_code: str = "VN") -> dict[str, Any]:
    """Build and persist the latest country product-by-geo opportunity snapshot."""
    repo = repo or MarketRepository()
    inputs = _load_refresh_inputs(country_code)
    prior_by_product = {row["product_id"]: row for row in inputs["priors"]}
    sales_by_key = build_sales_validation(inputs["rfq_rows"])
    competition_by_track = _competition_by_track(inputs["competition_rows"])
    products = repo.list_product_tracks()
    snapshot_id = str(uuid.uuid4())
    calculated_at = datetime.now(timezone.utc).isoformat()
    rows, matched = _build_summary_rows(
        inputs["geo_units"], products, prior_by_product, inputs["city_rows"],
        competition_by_track, sales_by_key, snapshot_id, calculated_at,
    )
    written = repo.upsert_market_potential_summaries(rows)
    return {"status": "updated", "country": country_code.upper(), "geo_units": len(inputs["geo_units"]),
            "products": len(products), "rows": len(rows), "written": written,
            "city_matches": matched, "city_match_radius_km": MAX_CITY_MATCH_KM,
            "model_version": MODEL_VERSION}


if __name__ == "__main__":
    print(json.dumps(refresh(), indent=2))
