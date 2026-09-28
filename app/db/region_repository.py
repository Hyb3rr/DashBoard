"""Persistence adapter for country market profiles and demand signals."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..core.regions import market_score, normalise_conflict_indicators, normalise_economic_indicators
from .json_codec import decode_json as _decode_json
from .json_codec import jsonb_value as _json
from .postgres import transaction


class RegionRepository:
    @staticmethod
    def _normalise(row: dict[str, Any]) -> dict[str, Any]:
        """Decode and normalize persisted national market indicator fields."""
        data = dict(row)
        data["economic_indicators"] = normalise_economic_indicators(_decode_json(data["economic_indicators"]))
        data["cultural_context"] = _decode_json(data["cultural_context"]) or []
        data["conflict_indicators"] = normalise_conflict_indicators(_decode_json(data["conflict_indicators"]))
        data["sources"] = _decode_json(data["sources"]) or []
        data.update(market_score(data))
        return data

    def seed(self, items: list[dict[str, Any]]) -> None:
        """Upsert a batch of country market profiles from a refreshed snapshot."""
        with transaction() as conn:
            for item in items:
                if not item.get("country_code") or not item.get("country_name"):
                    raise ValueError("region seed item missing country identity")
                conn.execute(
                    """INSERT INTO region_profiles
                       (country_code,country_name,economic_indicators,cultural_context,
                        conflict_indicators,sources,observed_ip_count,updated_at)
                       VALUES (%s,%s,%s,%s,%s,%s,COALESCE((SELECT observed_ip_count FROM region_profiles WHERE country_code = %s), 0),%s)
                       ON CONFLICT(country_code) DO UPDATE SET
                         country_name=EXCLUDED.country_name,
                         economic_indicators=EXCLUDED.economic_indicators,
                         cultural_context=EXCLUDED.cultural_context,
                         conflict_indicators=EXCLUDED.conflict_indicators,
                         sources=EXCLUDED.sources,
                         updated_at=EXCLUDED.updated_at""",
                    (
                        item["country_code"],
                        item["country_name"],
                        _json(normalise_economic_indicators(item.get("economic_indicators"))),
                        _json(item.get("cultural_context")),
                        _json(normalise_conflict_indicators(item.get("conflict_indicators"))),
                        _json(item.get("sources")),
                        item["country_code"],
                        item.get("updated_at") or "",
                    )
                )

    def get(self, country_code: str | None) -> dict[str, Any] | None:
        """Fetch one normalized country market profile by country code."""
        if not country_code:
            return None
        with transaction() as conn:
            row = conn.execute("SELECT * FROM region_profiles WHERE country_code = %s", (country_code.upper(),)).fetchone()
            if not row:
                return None
            data = self._normalise(dict(row))
            observed = conn.execute("SELECT COUNT(*) AS n FROM ip_profiles WHERE country_code = %s", (country_code.upper(),)).fetchone()
            data["observed_ip_count"] = observed["n"] if observed else data.get("observed_ip_count", 0)
            return data

    def list(self, limit: int = 50) -> list[dict[str, Any]]:
        """List normalized country market profiles ordered by country name."""
        with transaction() as conn:
            rows = conn.execute(
                """SELECT r.*,
                          (SELECT COUNT(*) FROM ip_profiles p
                            WHERE p.country_code = r.country_code) AS observed_ip_count
                     FROM region_profiles r
                    ORDER BY r.country_name ASC
                    LIMIT %s""",
                (limit,),
            ).fetchall()
        return [self._normalise(dict(row)) for row in rows if row["country_code"]]

    @staticmethod
    def _decode_demand_row(raw: Any) -> dict[str, Any]:
        """Decode JSON evidence and flatten joined demand fields for one IP."""
        item = dict(raw)
        for key in ("identity_evidence", "reputation", "evidence", "sources"):
            item[key] = _decode_json(item.get(key)) or []
        item["observation_payload"] = item.get("observation_payload") or {}
        item["classification_label"] = item.get("classification_label") or "unknown"
        return item

    def _new_demand_entry(self, code: str, item: dict[str, Any]) -> dict[str, Any]:
        """Create a country demand row with its market-profile context."""
        region = self.get(code) or {"country_code": code, "country_name": item.get("country") or code}
        return {
            "country_code": code,
            "country_name": region.get("country_name") or item.get("country") or code,
            "observed_ip_count": 0,
            "observed_requests": 0,
            "good_ip_count": 0,
            "classified_good_ip_count": 0,
            "good_requests": 0,
            "low_ip_count": 0,
            "medium_ip_count": 0,
            "critical_ip_count": 0,
            "unknown_ip_count": 0,
            "privacy_signal_ip_count": 0,
            "profile_updated_at": region.get("updated_at"),
            "economic_indicators": region.get("economic_indicators", {}),
            "market_components": region.get("market_components", {}),
            "market_score": region.get("market_score"),
            "market_level": region.get("market_level", "unknown"),
            "product_opportunities": region.get("product_opportunities", []),
            "cultural_context": region.get("cultural_context", []),
            "conflict_indicators": region.get("conflict_indicators", []),
            "sources": region.get("sources", []),
        }

    @staticmethod
    def _accumulate_demand_ip(entry: dict[str, Any], item: dict[str, Any]) -> None:
        """Add one IP's observed traffic and qualified-good signals to a country."""
        label = item["classification_label"]
        observation = item["observation_payload"]
        requests = int(observation.get("requests") or 0)
        entry["observed_ip_count"] += 1
        entry["observed_requests"] += requests
        if label == "good":
            entry["classified_good_ip_count"] += 1
        else:
            entry[f"{label}_ip_count"] += 1

        privacy_signal = any(
            item.get(field) is True or item.get(field) == 1
            for field in ("is_tor", "is_vpn", "is_proxy", "is_hosting")
        )
        if privacy_signal:
            entry["privacy_signal_ip_count"] += 1

        eligible = (
            label == "good" and requests > 0 and not privacy_signal
            and int(observation.get("sensitive_probe_requests") or 0) == 0
            and int(observation.get("bot_requests") or 0) == 0
        )
        if eligible:
            entry["good_requests"] += requests
            entry["good_ip_count"] += 1

    @staticmethod
    def _finalize_demand_entries(aggregates: dict[str, dict[str, Any]], limit: int) -> list[dict[str, Any]]:
        """Calculate country demand summaries and return the top limited rows."""
        results = []
        for entry in aggregates.values():
            total = entry["observed_requests"]
            good_ips = entry["good_ip_count"]
            entry["good_traffic_share"] = round(entry["good_requests"] / total, 4) if total else 0
            entry["signal_level"] = (
                "high" if entry["good_requests"] >= 500 else
                "medium" if entry["good_requests"] >= 50 else
                "low" if entry["good_requests"] > 0 else "none"
            )
            entry["product_demand"] = (entry.get("market_components") or {}).get("product_demand")
            entry["analyst_note"] = "Observed good traffic signal; validate with conversion and customer data before market decisions." if good_ips else "No qualifying good traffic observed in the current window."
            results.append(entry)
        results.sort(key=lambda row: (row["good_requests"], row["observed_requests"]), reverse=True)
        return results[:limit]

    def demand_signal(self, limit: int = 50) -> list[dict[str, Any]]:
        """Aggregate observed qualified traffic by country for market context."""
        with transaction() as conn:
            rows = conn.execute("""
                SELECT p.*, o.payload AS observation_payload, cs.label AS classification_label
                FROM ip_profiles p
                LEFT JOIN ip_observations_state o ON o.ip = p.ip
                LEFT JOIN ip_classification_state cs ON cs.ip = p.ip
                WHERE p.country_code IS NOT NULL
            """).fetchall()
        aggregates: dict[str, dict[str, Any]] = {}
        for raw in rows:
            item = self._decode_demand_row(raw)
            code = item["country_code"]
            if code not in aggregates:
                aggregates[code] = self._new_demand_entry(code, item)
            self._accumulate_demand_ip(aggregates[code], item)
        return self._finalize_demand_entries(aggregates, limit)
