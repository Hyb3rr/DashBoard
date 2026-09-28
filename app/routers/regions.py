from fastapi import APIRouter, HTTPException

from ..db.repositories import RegionRepository
from ..db.market_repository import MarketRepository
from ..services.province_profile import build_vietnam_province_profile
from ..core.country_demand import build_country_opportunities

router = APIRouter()


@router.get("/api/regions")
def region_list(limit: int = 50):
    """Return stored country region profiles up to the requested limit."""
    return RegionRepository().list(limit=min(max(limit, 1), 250))


@router.get("/api/regions/demand-signal")
def region_demand_signal(limit: int = 50):
    """Return country demand signals derived from qualified observed traffic."""
    return RegionRepository().demand_signal(min(max(limit, 1), 200))


@router.get("/api/country-demand-signals")
def country_demand_signals(period: str = "30d"):
    """Return the published country-demand snapshot for a supported period."""
    if period not in {"7d", "30d", "90d"}:
        raise HTTPException(400, "unsupported country demand period")
    snapshot = MarketRepository().list_latest_country_demand_signals(period)
    if not snapshot:
        return {"period": period, "status": "unavailable", "countries": []}
    snapshot["status"] = "published"
    return snapshot


@router.get("/api/country-opportunities")
def country_opportunities(period: str = "30d"):
    """Combine country market scores with published demand snapshots."""
    if period not in {"7d", "30d", "90d"}:
        raise HTTPException(400, "unsupported country demand period")
    snapshots = {period: MarketRepository().list_latest_country_demand_signals(period) for period in ("7d", "30d", "90d")}
    regions = RegionRepository().list(limit=250)
    market_scores = {str(item.get("country_code") or "").upper(): item for item in regions if item.get("country_code")}
    result = build_country_opportunities(snapshots, market_scores, period=period)
    result["status"] = "published" if snapshots.get(period) else "unavailable"
    return result


@router.get("/api/regions/{country_code}")
def region_details(country_code: str):
    """Return country context, local opportunity layers, and published snapshots."""
    code = country_code.upper()
    data = RegionRepository().get(code)
    if not data:
        raise HTTPException(404, "Region profile not found")
    market = MarketRepository()
    local = market.list_local_opportunities_for_api(code)
    overlap = market.list_area_overlap_for_api(code)
    areas = market.list_area_opportunity_summaries(code)
    cities = market.list_city_opportunity_summaries(code)
    product_market = market.list_market_potential_summaries(code)
    industrial_snapshot = (market.get_latest_industrial_demand_snapshot(code)
                           if hasattr(market, "get_latest_industrial_demand_snapshot") else None)
    industrial_evidence = (market.list_latest_industrial_demand_evidence(
        code, str(industrial_snapshot["snapshot_id"]))
                           if industrial_snapshot and hasattr(market, "list_latest_industrial_demand_evidence") else [])
    data["area_opportunities"] = areas
    data["city_opportunities"] = cities
    data["city_status"] = "ready" if cities else "unavailable"
    data["city_unavailable_reason"] = None if cities else "insufficient_city_summary"
    data["market_product_opportunities"] = product_market
    data["industrial_demand"] = {
        "status": "published" if industrial_snapshot else "unavailable",
        "model_version": industrial_snapshot.get("model_version") if industrial_snapshot else None,
        "snapshot_id": (str(industrial_snapshot["snapshot_id"]) if industrial_snapshot else None),
        "evidence": industrial_evidence,
    }
    data["province_profile"] = build_vietnam_province_profile(include_overall=False) if code == "VN" else None
    data["city_overall_snapshot"] = None
    if code == "VN":
        snapshot = market.latest_city_overall_snapshot(code)
        if snapshot:
            by_geo = {str(row["geo_unit_id"]): row for row in snapshot.get("rows", [])}
            for province in data["province_profile"].get("provinces", []):
                row = by_geo.get(str(province.get("geo_unit_id")))
                if row:
                    province["city_overall_opportunity"] = {
                        "score": row.get("score"),
                        "evidence_coverage": row.get("evidence_coverage"),
                        "components": row.get("components") or {},
                        "limitations": row.get("limitations") or [],
                        "model_version": snapshot.get("model_version"),
                        "snapshot_id": str(snapshot.get("snapshot_id")),
                        "calculated_at": snapshot.get("calculated_at"),
                        "peer_group": snapshot.get("peer_group"),
                    }
            data["city_overall_snapshot"] = {
                "snapshot_id": str(snapshot.get("snapshot_id")),
                "model_version": snapshot.get("model_version"),
                "peer_group": snapshot.get("peer_group"),
                "calculated_at": snapshot.get("calculated_at"),
            }
    data["local_opportunities"] = local
    data["overlap"] = overlap
    data["overlap_status"] = "ready" if overlap else "unavailable"
    data["overlap_unavailable_reason"] = None if overlap else "insufficient_local_hierarchy"
    return data
