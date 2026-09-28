"""Batch service boundary for country demand signal snapshots."""

from __future__ import annotations

from typing import Any, Iterable
from uuid import uuid4
from datetime import datetime, timedelta, timezone

from ..core.country_demand import CountryDemandConfig, aggregate_country_demand, aggregate_session_observations
from ..config import settings
from ..db import clickhouse
from ..db.repositories import ProfileRepository


def _normalize_observation(raw: dict[str, Any], metadata: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize one traffic row with its IP profile context for aggregation."""
    profile = metadata.get(str(raw.get("src_ip")))
    cf_country = str(raw.get("cf_country") or "").upper()
    profile_country = str((profile or {}).get("country_code") or "").upper()
    country = cf_country or profile_country
    if not country:
        return None
    network_type = str((profile or {}).get("network_type") or "").lower()
    path = str(raw.get("path") or "").split("?", 1)[0]
    return {
        "country_code": country,
        "country_source": raw.get("country_source") or ("cloudflare" if cf_country else "profile"),
        "visitor_id": raw.get("visitor_id"),
        "identity_method": raw.get("identity_method") or "none",
        "session_id": raw.get("session_id"),
        "product_page": path.startswith(("/products/", "/product/", "/danh-muc/")),
        **_network_context(raw, profile, network_type),
        **_engagement_context(raw),
    }


def _optional_event_bool(raw: dict[str, Any], key: str, fallback: Any = None) -> Any:
    """Prefer an explicit event flag and otherwise use its profile fallback."""
    return bool(raw[key]) if raw.get(key) is not None else fallback


def _network_context(raw: dict[str, Any], profile: dict | None, network_type: str) -> dict[str, Any]:
    """Normalize bot and network identity signals with profile-derived fallbacks."""
    return {
        "cf_bot_score": raw.get("cf_bot_score"),
        "cf_js_detection_passed": _optional_event_bool(raw, "cf_js_detection_passed"),
        "is_tor": _optional_event_bool(raw, "is_tor", (profile or {}).get("is_tor")),
        "is_hosting": _optional_event_bool(raw, "is_hosting", (profile or {}).get("is_hosting")),
        "business_isp": network_type == "business",
        "is_vpn": _optional_event_bool(raw, "is_vpn", (profile or {}).get("is_vpn")),
        "is_proxy": _optional_event_bool(raw, "is_proxy", (profile or {}).get("is_proxy")),
        "is_mobile": _optional_event_bool(raw, "is_mobile", network_type == "mobile" if profile else None),
        "is_scanner": _optional_event_bool(raw, "is_scanner"),
        "geo_confidence": raw.get("geo_confidence"),
        "geo_conflict": _optional_event_bool(raw, "geo_conflict"),
        "cgnat": network_type == "mobile",
        "mobile_carrier": network_type == "mobile",
        "malicious_ip": str((profile or {}).get("label") or "") == "malicious",
    }


def _engagement_context(raw: dict[str, Any]) -> dict[str, Any]:
    """Select engagement, page-view, and conversion counters from one event."""
    return {
        "engaged": _optional_event_bool(raw, "engaged"),
        "engagement_seconds": raw.get("engagement_seconds"),
        "pageviews": raw.get("pageviews"),
        "key_event_count": raw.get("key_event_count"),
    }


class CountryDemandService:
    """Build demand snapshots from already normalized batch observations.

    ClickHouse extraction and PostgreSQL persistence belong to the caller's
    scheduled job; this service stays deterministic and request-path free.
    """

    def __init__(self, config: CountryDemandConfig | None = None) -> None:
        """Initialize the service with the supplied or default scoring policy."""
        self.config = config or CountryDemandConfig()

    def build_snapshot(
        self,
        current_events: Iterable[dict[str, Any]],
        previous_events: Iterable[dict[str, Any]],
        *,
        period: str = "30d",
    ) -> dict[str, Any]:
        """Aggregate current and prior observations into a demand snapshot."""
        return aggregate_country_demand(
            current_events,
            previous_events,
            period=period,
            config=self.config,
        )

    def publish_snapshot(
        self,
        repository: Any,
        current_events: Iterable[dict[str, Any]],
        previous_events: Iterable[dict[str, Any]],
        *,
        period: str = "30d",
        snapshot_id: str | None = None,
    ) -> dict[str, Any]:
        """Publish atomically after the full country batch has been written."""
        snapshot_id = snapshot_id or str(uuid4())
        snapshot = self.build_snapshot(current_events, previous_events, period=period)
        repository.create_country_demand_snapshot(snapshot_id, period, self.config.min_sample_size)
        count = repository.write_country_demand_signals(snapshot_id, snapshot["countries"])
        if not repository.publish_country_demand_snapshot(snapshot_id, count):
            raise RuntimeError("country demand snapshot was not published")
        return {"snapshot_id": snapshot_id, "period": period, "country_count": count, "status": "published"}

    def refresh(self, repository: Any, *, now: datetime | None = None, period: str = "30d") -> dict[str, Any]:
        """Build one bounded snapshot from ClickHouse raw events and PG metadata."""
        period_days = {"7d": 7, "30d": 30, "90d": 90}
        if period not in period_days:
            raise ValueError("unsupported country demand period")
        end = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        current_start = end - timedelta(days=period_days[period])
        previous_start = current_start - timedelta(days=period_days[period])
        rows = clickhouse.country_demand_events(current_start, end, settings.DATASET_LIVE_ID)
        previous_rows = clickhouse.country_demand_events(previous_start, current_start, settings.DATASET_LIVE_ID)
        metadata = ProfileRepository().country_demand_metadata({str(row.get("src_ip")) for row in rows + previous_rows})
        current = aggregate_session_observations(item for row in rows if (item := _normalize_observation(row, metadata)) is not None)
        previous = aggregate_session_observations(item for row in previous_rows if (item := _normalize_observation(row, metadata)) is not None)
        if not current:
            return {"status": "no_data", "period": period, "country_count": 0}
        return self.publish_snapshot(repository, current, previous, period=period)


__all__ = ["CountryDemandService"]
