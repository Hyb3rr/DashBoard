"""Resolve infrastructure location from local prefix and vendor snapshots.

Design note (2026-08): registration data (RIR/WHOIS) answers "who administers
this address space", not "where is this IP operating today". Earlier versions
of this resolver let a `rir` candidate (weight 72) vote directly against a
`maxmind` candidate (weight 60) in the same country-consensus pool. That is
semantically wrong for any multi-region network (Microsoft/AWS/Google/Cloudflare
style ASNs): the RIR entry is almost always the corporate HQ country, which has
nothing to do with which datacenter is actually announcing the prefix, so it
would systematically win against a single vendor GeoIP source and produce a
false "disputed" status.

This module now keeps two separate evidence pools:

  * `registration` - RIR/WHOIS/RDAP "who owns this" data. Reported for
    context and used only as a last-resort operational estimate when nothing
    else exists.
  * `operational`  - everything that actually claims to know where the
    network is *running* (geofeed, cloud/CDN official region data, MaxMind,
    IPinfo, DB-IP, PTR/BGP PoP hints, ...). This is the pool used to decide
    `country` / `country_code` / `disputed`.

Within the operational pool there is still a tier order: geofeed and
cloud-official region data are treated as owner-declared fact and override a
statistical vendor vote (see `_select_operational_pool`).
"""
from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timedelta, timezone


SOURCE_WEIGHTS = {
    "geofeed": 95,
    "cloud_official": 92,
    "rir": 72,
    "peeringdb": 68,
    "maxmind": 60,
    "vendor": 55,
}
GEO_RULESET_VERSION = "geo-v3"

# A network whose operational country flips this many times inside the
# lookback window is more likely anycast / actively re-homed than simply
# "wrong" in one snapshot; flag it instead of just penalizing confidence.
VOLATILITY_FLAP_THRESHOLD = 2
VOLATILITY_LOOKBACK_DAYS = 30
VOLATILITY_PENALTY = 10


def _source_weight(source: str) -> int:
    for key, weight in SOURCE_WEIGHTS.items():
        if key in source.lower():
            return weight
    return 45


def _country_name(code: str | None) -> str | None:
    if not code:
        return None
    try:
        import pycountry

        country = pycountry.countries.get(alpha_2=code.upper())
        return country.name if country else code.upper()
    except ImportError:
        return code.upper()


def _candidate(country_code: str | None, source: str, **values) -> dict | None:
    if not country_code:
        return None
    code = country_code.upper()
    return {
        "country_code": code,
        "country": values.get("country") or _country_name(code),
        "source": source,
        "confidence": int(values.get("confidence", _source_weight(source))),
        "scope": values.get("scope", "network"),
        **{key: values.get(key) for key in ("latitude", "longitude", "city")},
    }


def _select_operational_pool(operational_candidates: list[dict]) -> tuple[list[dict], str]:
    """Pick which operational evidence gets to vote, in tier order.

    Tier A (owner-declared, override): geofeed, then cloud/CDN official
    region data. Tier B (statistical consensus): every remaining operational
    source (MaxMind, IPinfo, DB-IP, PTR/BGP hints, PeeringDB, ...) voted
    together, weighted by source confidence.
    """
    geofeed = [item for item in operational_candidates if "geofeed" in item["source"].lower()]
    if geofeed:
        return geofeed, "geofeed"
    cloud_official = [
        item for item in operational_candidates
        if "cloud" in item["source"].lower() and item["scope"] == "datacenter"
    ]
    if cloud_official:
        return cloud_official, "cloud_official"
    if operational_candidates:
        return operational_candidates, "vendor_consensus"
    return [], "none"


def _rank(pool: list[dict]) -> list[tuple]:
    grouped: dict[str, list[dict]] = {}
    for candidate in pool:
        grouped.setdefault(candidate["country_code"], []).append(candidate)
    ranked = []
    for code, items in grouped.items():
        weighted = sum(item["confidence"] for item in items)
        best = max(items, key=lambda item: item["confidence"])
        ranked.append((weighted, best["confidence"], code, best, items))
    ranked.sort(reverse=True, key=lambda item: (item[0], item[1]))
    return ranked


def _flap_count(conn, network: str | None, lookback_days: int = VOLATILITY_LOOKBACK_DAYS) -> int:
    """How many recorded country changes this network had recently.

    Frequent flapping is a signal the network is anycast or being actively
    re-homed, not that any single resolution is "wrong". Best-effort: if the
    change-history table is unavailable for any reason, treat as unknown (0)
    rather than failing the whole resolution.
    """
    if not network:
        return 0
    try:
        since = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).isoformat()
        row = conn.execute(
            "SELECT COUNT(*) AS c FROM geo_change_history WHERE network=? AND detected_at>=?",
            (network, since),
        ).fetchone()
        return int(row["c"]) if row else 0
    except Exception:
        return 0


def resolve_network_location(conn, ip: str, vendor: dict | None = None) -> dict:
    """Resolve one IP using only local SQLite snapshots and optional vendor data."""
    address = ipaddress.ip_address(ip)
    prefixes = []
    for row in conn.execute("SELECT * FROM geo_prefixes WHERE active=1"):
        try:
            if address in ipaddress.ip_network(row["network"], strict=False):
                prefixes.append(dict(row))
        except ValueError:
                continue

    identity = {}
    if not prefixes:
        try:
            from ..providers.bgp_pyasn import lookup as pyasn_lookup

            snapshot = pyasn_lookup(str(address))
            if snapshot:
                identity.update({"asn": snapshot.get("asn"), "ip_prefix": snapshot.get("ip_prefix")})
        except Exception:
            pass

    registration_candidates: list[dict] = []
    operational_candidates: list[dict] = []
    network = None
    for prefix in sorted(prefixes, key=lambda item: ipaddress.ip_network(item["network"]).prefixlen, reverse=True):
        network = network or prefix["network"]
        identity.setdefault("asn", prefix.get("asn"))
        identity.setdefault("organization", prefix.get("organization"))
        identity.setdefault("network_type", prefix.get("network_type"))
        # Registration/ownership evidence (RIR, WHOIS, RDAP): answers "who
        # administers this address space", kept out of the operational vote.
        if prefix.get("registration_country"):
            registration_candidates.append(_candidate(
                prefix["registration_country"], prefix.get("source", "rir"), scope="registration",
            ))
        # Operational evidence: geofeed, cloud/CDN region data, MaxMind,
        # IPinfo, DB-IP, PTR/BGP hints, etc - whatever the updater recorded
        # against this prefix as "where it actually runs".
        for location in conn.execute(
            "SELECT * FROM geo_location_observations WHERE network=?", (prefix["network"],)
        ):
            operational_candidates.append(_candidate(
                location["country_code"],
                location["source"],
                country=location["country"],
                confidence=location["source_confidence"],
                scope=location["location_scope"],
                latitude=location["latitude"],
                longitude=location["longitude"],
                city=location["city"],
            ))

    vendor = vendor or {}
    if vendor.get("country_code"):
        operational_candidates.append(_candidate(
            vendor.get("country_code"),
            vendor.get("geo_source", "maxmind"),
            country=vendor.get("country"),
            confidence=int(vendor.get("geo_confidence") or _source_weight(vendor.get("geo_source", "maxmind"))),
            scope="vendor",
            latitude=vendor.get("latitude"),
            longitude=vendor.get("longitude"),
            city=vendor.get("city"),
        ))

    registration_candidates = [c for c in registration_candidates if c]
    operational_candidates = [c for c in operational_candidates if c]
    all_candidates = registration_candidates + operational_candidates

    # Best single registration record, kept for context/output regardless of
    # which tier wins the operational vote. Registration never competes with
    # operational evidence for the winning country.
    registration_best = max(registration_candidates, key=lambda item: item["confidence"], default=None)
    registration_info = None
    if registration_best:
        registration_info = {
            "country": registration_best["country"],
            "country_code": registration_best["country_code"],
            "source": registration_best["source"],
        }

    if not all_candidates:
        return {
            "network": network,
            **identity,
            "country": vendor.get("country"),
            "country_code": vendor.get("country_code"),
            "latitude": vendor.get("latitude"),
            "longitude": vendor.get("longitude"),
            "city": vendor.get("city"),
            "confidence": 0,
            "disputed": False,
            "scope": "vendor" if vendor.get("country_code") else "unknown",
            "sources": [],
            "candidates": [],
            "registration": registration_info,
            "allocation_pattern": "registration_unavailable" if not registration_info else "no_operational_evidence",
            "operational_tier": "none",
            "volatile_location": False,
            "confidence_breakdown": {
                "method": "no_agreement",
                "final_score": 0,
                "formula": "No country candidates were available.",
                "sources": [],
            },
        }

    pool, tier = _select_operational_pool(operational_candidates)
    used_registration_fallback = False
    if not pool:
        # No operational evidence at all (no geofeed, no vendor GeoIP, no
        # cloud region data) - fall back to registration as a weak estimate,
        # rather than returning nothing. This is explicitly the *last*
        # resort, not a competing vote against operational sources.
        pool = registration_candidates
        tier = "registration_fallback"
        used_registration_fallback = True

    ranked = _rank(pool)
    winner = ranked[0]
    runner = ranked[1] if len(ranked) > 1 else None
    disputed = bool(runner and winner[0] - runner[0] < 20)
    best = winner[3]
    confidence = min(100, max(best["confidence"], int(winner[0] / max(len(winner[4]), 1))))
    base_confidence = confidence
    agreement_bonus = min(16, max(0, (len(winner[4]) - 1) * 8))
    confidence = min(100, confidence + agreement_bonus)
    dispute_penalty = 0
    if disputed:
        confidence = max(0, confidence - 20)
        dispute_penalty = 20

    if used_registration_fallback:
        # Registration country is a weak proxy for operational location -
        # cap confidence so it never reads as strongly as real operational
        # evidence would have.
        confidence = min(confidence, 55)

    flap_count = _flap_count(conn, network)
    volatile_location = flap_count >= VOLATILITY_FLAP_THRESHOLD
    volatility_penalty = 0
    if volatile_location:
        volatility_penalty = VOLATILITY_PENALTY
        confidence = max(0, confidence - volatility_penalty)

    allocation_pattern = "consistent"
    if used_registration_fallback:
        allocation_pattern = "registration_estimate_only"
    elif registration_info and registration_info["country_code"] != winner[2]:
        allocation_pattern = "cross_region_allocation"
    elif not registration_info:
        allocation_pattern = "registration_unavailable"

    source_ids = sorted({item["source"] for item in all_candidates})
    confidence_breakdown = {
        "method": "weighted_country_consensus",
        "operational_tier": tier,
        "final_score": confidence,
        "winner_country_code": winner[2],
        "winner_weight": winner[0],
        "runner_up": {"country_code": runner[2], "weight": runner[0]} if runner else None,
        "base_score_before_dispute_penalty": base_confidence,
        "agreement_bonus": agreement_bonus,
        "dispute_penalty": dispute_penalty,
        "volatility_flap_count": flap_count,
        "volatility_penalty": volatility_penalty,
        "registration_excluded_from_vote": not used_registration_fallback and bool(registration_candidates),
        "formula": (
            "Registration (RIR/WHOIS) evidence is scored separately and never competes "
            "with operational evidence for country/confidence, except as a last-resort "
            "estimate when no operational evidence exists at all. Within the operational "
            "pool: geofeed overrides cloud-official overrides a weighted vendor vote. "
            "Score = max(best source confidence, average weighted confidence) plus 8 per "
            "agreeing source (max +16), minus 20 when the runner-up is within 20 points, "
            "minus 10 if the network's country has flapped repeatedly in the last "
            f"{VOLATILITY_LOOKBACK_DAYS} days."
        ),
        "sources": [
            {
                "source": item["source"],
                "country_code": item["country_code"],
                "confidence": item["confidence"],
                "scope": item["scope"],
            }
            for item in all_candidates
        ],
    }
    return {
        "network": network,
        **identity,
        "country": best["country"],
        "country_code": winner[2],
        "latitude": best.get("latitude"),
        "longitude": best.get("longitude"),
        "city": best.get("city"),
        "confidence": confidence,
        "disputed": disputed,
        "scope": best["scope"],
        "sources": source_ids,
        "candidates": all_candidates,
        "registration": registration_info,
        "allocation_pattern": allocation_pattern,
        "operational_tier": tier,
        "volatile_location": volatile_location,
        "confidence_breakdown": confidence_breakdown,
    }


def persist_resolution(conn, ip: str, resolution: dict, ttl_days: int = 14) -> None:
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=max(1, ttl_days))
    previous = conn.execute("SELECT * FROM geo_resolutions WHERE ip=?", (ip,)).fetchone()
    if previous and previous["country_code"] != resolution.get("country_code"):
        conn.execute(
            """INSERT INTO geo_change_history
               (ip,network,previous_country_code,country_code,previous_confidence,confidence,detected_at,evidence_json)
               VALUES(?,?,?,?,?,?,?,?)""",
            (ip, resolution.get("network"), previous["country_code"], resolution.get("country_code"),
             previous["confidence"], resolution.get("confidence", 0), now.isoformat(), json.dumps(resolution, default=str)),
        )
    conn.execute(
        """INSERT INTO geo_resolutions
           (ip,network,asn,organization,network_type,country,country_code,latitude,longitude,city,
            confidence,disputed,location_scope,source_ids_json,resolved_at,expires_at,ruleset_version,evidence_json)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(ip) DO UPDATE SET network=excluded.network,asn=excluded.asn,
            organization=excluded.organization,network_type=excluded.network_type,country=excluded.country,
            country_code=excluded.country_code,latitude=excluded.latitude,longitude=excluded.longitude,
            city=excluded.city,confidence=excluded.confidence,disputed=excluded.disputed,
            location_scope=excluded.location_scope,source_ids_json=excluded.source_ids_json,
            resolved_at=excluded.resolved_at,expires_at=excluded.expires_at,
            ruleset_version=excluded.ruleset_version,evidence_json=excluded.evidence_json""",
            (ip, resolution.get("network"), resolution.get("asn"), resolution.get("organization"), resolution.get("network_type"),
         resolution.get("country"), resolution.get("country_code"), resolution.get("latitude"), resolution.get("longitude"),
         resolution.get("city"), resolution.get("confidence", 0), int(resolution.get("disputed", False)), resolution.get("scope", "unknown"),
         json.dumps(resolution.get("sources", [])), now.isoformat(), expires.isoformat(), GEO_RULESET_VERSION, json.dumps(resolution, default=str)),
    )