import asyncio
from datetime import datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path
from typing import Any

from ..config.settings import TOR_EXIT_LIST
from .evidence import UnifiedEvidence
from .enrichment_geo import apply_geo_resolution as _apply_geo_resolution
from .enrichment_geo import normalize_geo_candidates as _normalize_geo_candidates
from .enrichment_policy import (
    abuse_reputation_state,
    anonymization_summary as _anonymization_summary,
    append_geo_configuration_warning as _append_geo_configuration_warning,
    enrichment_statuses as _enrichment_statuses,
    identity_confidence as _identity_confidence,
    intel_tags_for_abuse,
    network_flags as _network_flags,
    risk as _risk,
    status_from_fields as _status_from_fields,
)
from ..services.geo_bounds import bounds_for
from ..services.geo_resolution import resolve_geo_records
from ..services.geo_validation import validate_records
from ..services.geonames_hierarchy import GeoNamesHierarchy


def resolve_network_location(ip: str, vendor: dict | None = None, force_refresh: bool = False) -> dict:
    """Resolve an IP through the PostgreSQL-backed network location store."""
    from ..db.pg_intelligence import resolve_network_location as resolve_pg
    return resolve_pg(str(ip), vendor, force_refresh=force_refresh)


try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

_reader_cache: dict[tuple[str, str], object] = {}
_tor_cache: dict[str, tuple[float, set[str]]] = {}
_cidr_cache: dict[str, tuple[float, tuple[ipaddress._BaseNetwork, ...]]] = {}
_geo_hierarchy_cache: dict[str, GeoNamesHierarchy | None] = {}


def _now() -> str:
    """Return the current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _address_scope(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Classify an IP address by its special-use or public scope."""
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if address.is_unspecified:
        return "unspecified"
    if address.is_reserved:
        return "reserved"
    if address.version == 4 and address in ipaddress.ip_network("100.64.0.0/10"):
        return "shared_cgnat"
    if address.version == 4 and address in ipaddress.ip_network("192.0.2.0/24"):
        return "documentation"
    if address.version == 4 and address in ipaddress.ip_network("198.51.100.0/24"):
        return "documentation"
    if address.version == 4 and address in ipaddress.ip_network("203.0.113.0/24"):
        return "documentation"
    if address.version == 6 and address in ipaddress.ip_network("2001:db8::/32"):
        return "documentation"
    if address.is_private:
        return "private"
    return "public"


def _geo_hierarchy() -> GeoNamesHierarchy | None:
    """Load and cache the optional GeoNames administrative hierarchy."""
    path_text = os.getenv("GEONAMES_HIERARCHY_PATH", "data/geonames/hierarchy.json").strip()
    if not path_text:
        return None
    if path_text in _geo_hierarchy_cache:
        return _geo_hierarchy_cache[path_text]
    try:
        hierarchy = GeoNamesHierarchy.from_path(path_text)
    except (OSError, ValueError, TypeError, KeyError):
        hierarchy = None
    _geo_hierarchy_cache[path_text] = hierarchy
    return hierarchy


def _present(value) -> bool:
    """Return whether an enrichment value is available."""
    return value is not None and value != ""


def build_enrichment_evidence(data: dict[str, Any], observed_at: str | None = None) -> list[dict[str, Any]]:
    """Adapt local enrichment signals without changing legacy profile fields."""
    timestamp = observed_at or data.get("fetched_at") or _now()
    result: list[dict[str, Any]] = []
    privacy = {key: data.get(key) for key in ("is_tor", "is_vpn", "is_proxy", "is_hosting") if data.get(key) is not None}
    if privacy:
        result.append(UnifiedEvidence(
            source="privacy", type="privacy", severity="supporting", observed=privacy,
            baseline={"source": "local provider state"}, score_contribution=0,
            observed_at=timestamp, description="Privacy and hosting signals from local intelligence.",
            supporting_context={"sources": data.get("sources", [])},
        ).to_dict())
    reputation = data.get("abuse_reputation") or data.get("reputation")
    if reputation:
        result.append(UnifiedEvidence(
            source="reputation", type="reputation", severity="supporting", observed={"state": reputation},
            baseline={"source": "local reputation state"}, score_contribution=0,
            observed_at=timestamp, description="Reputation context from persisted intelligence.",
            supporting_context={"provider_status": data.get("provider_status", {})},
        ).to_dict())
    geo = {key: data.get(key) for key in ("country", "country_code", "asn", "organization", "network_type") if _present(data.get(key))}
    if geo:
        result.append(UnifiedEvidence(
            source="geo_network", type="geo_network", severity="supporting", observed=geo,
            baseline={"location_scope": data.get("location_scope", "network")}, score_contribution=0,
            observed_at=timestamp, description="Geo and network identity context from local intelligence.",
            supporting_context={"confidence": data.get("organization_confidence", 0), "field_sources": data.get("field_sources", {})},
        ).to_dict())
    return result


def _reader(kind: str, path: str, factory):
    """Reuse a local database reader for the same provider and path."""
    key = (kind, path)
    cached = _reader_cache.get(key)
    if cached is None:
        cached = factory(path)
        _reader_cache[key] = cached
    return cached


def _merge(base: dict, incoming: dict, provider: str, field_sources: dict) -> list[str]:
    """Fill missing profile fields while recording their source."""
    filled = []
    for field, value in incoming.items():
        if _present(value) and not _present(base.get(field)):
            base[field] = value
            field_sources[field] = provider
            filled.append(field)
    return filled


def _provider_state(status: dict, name: str, state: str, error: str | None = None) -> None:
    """Record a configured provider's latest local lookup status."""
    if state == "not_configured":
        return
    status[name] = {"status": state, "checked_at": _now()}
    if error:
        status[name]["error"] = error


def _anonymous_ip(ip: str) -> tuple[dict, list[str], str]:
    """Read optional VPN, proxy, Tor, and hosting flags from MaxMind."""
    path = os.getenv("MAXMIND_ANONYMOUS_DB", "").strip()
    if not path:
        return {}, [], "not_configured"
    if not Path(path).is_file():
        return {}, [f"MaxMind Anonymous IP: database file missing: {path}"], "failed"
    try:
        import geoip2.database
        reader = _reader("maxmind_anonymous", path, geoip2.database.Reader)
        record = reader.anonymous(ip)
        result = {
            "is_vpn": bool(record.is_anonymous_vpn),
            "is_proxy": bool(record.is_public_proxy or record.is_residential_proxy),
            "proxy_type": "residential" if record.is_residential_proxy else "datacenter" if record.is_public_proxy else None,
            "is_tor": bool(record.is_tor_exit_node),
            "is_hosting": bool(record.is_hosting_provider),
        }
        return result, [], "active"
    except ImportError:
        return {}, ["MaxMind Anonymous IP: geoip2 package is not installed"], "failed"
    except Exception as exc:
        return {}, [f"MaxMind Anonymous IP: {type(exc).__name__}: {exc}"], "failed"


def _cidr_flag(ip: str, env_name: str, label: str) -> tuple[dict, list[str], str]:
    """Check an IP against a configured local VPN or proxy CIDR list."""
    path = os.getenv(env_name, "").strip()
    if not path:
        return {}, [], "not_configured"
    list_path = Path(path)
    if not list_path.is_file():
        return {}, [f"{label}: list file missing: {path}"], "failed"
    try:
        mtime = list_path.stat().st_mtime
        cached = _cidr_cache.get(path)
        if not cached or cached[0] != mtime:
            networks = []
            for raw in list_path.read_text(encoding="utf-8").splitlines():
                value = raw.split("#", 1)[0].strip()
                if not value:
                    continue
                try:
                    networks.append(ipaddress.ip_network(value, strict=False))
                except ValueError:
                    continue
            _cidr_cache[path] = (mtime, tuple(networks))
        matched = any(ipaddress.ip_address(ip) in network for network in _cidr_cache[path][1])
        field = "is_vpn" if "VPN" in label.upper() else "is_proxy"
        return ({field: True} if matched else {}), [], "active"
    except Exception as exc:
        return {}, [f"{label}: {type(exc).__name__}: {exc}"], "failed"


def _local_intelligence(ip: str) -> tuple[dict, dict, dict, list[str]]:
    """Read normalized intelligence snapshot from PostgreSQL."""
    from ..db.pg_intelligence import local_intelligence
    return local_intelligence(ip)


def _maxmind(ip: str) -> tuple[dict, list[str], str]:
    """Read configured local MaxMind City and ASN databases."""
    city_path = os.getenv("MAXMIND_CITY_DB")
    asn_path = os.getenv("MAXMIND_ASN_DB")
    if not city_path and not asn_path:
        return {}, [], "not_configured"

    try:
        import geoip2.database
    except ImportError:
        return {}, ["MaxMind: geoip2 package is not installed"], "failed"

    result, errors = {}, []

    if city_path:
        if not Path(city_path).is_file():
            errors.append(f"MaxMind City: database file missing: {city_path}")
        else:
            try:
                reader = _reader("maxmind_city", city_path, geoip2.database.Reader)
                record = reader.city(ip)
                result.update({
                    "country": record.country.name,
                    "country_code": record.country.iso_code,
                    "city": record.city.name,
                    "region": record.subdivisions.most_specific.name,
                    "latitude": record.location.latitude,
                    "longitude": record.location.longitude,
                    "timezone": record.location.time_zone,
                })
            except Exception as exc:
                errors.append(f"MaxMind City: {type(exc).__name__}: {exc}")

    if asn_path:
        if not Path(asn_path).is_file():
            errors.append(f"MaxMind ASN: database file missing: {asn_path}")
        else:
            try:
                reader = _reader("maxmind_asn", asn_path, geoip2.database.Reader)
                record = reader.asn(ip)
                number = record.autonomous_system_number
                result.update({
                    "asn": f"AS{number}" if number is not None else None,
                    "organization": record.autonomous_system_organization,
                })
            except Exception as exc:
                errors.append(f"MaxMind ASN: {type(exc).__name__}: {exc}")

    state = "active" if result else ("failed" if errors else "not_configured")
    return result, errors, state


def _tor_exit_list(ip: str) -> tuple[dict, list[str], str]:
    """Check a local Tor exit list and cache its parsed contents."""
    path = os.getenv("TOR_EXIT_LIST_PATH")
    if not path:
        default = TOR_EXIT_LIST
        path = str(default) if default.is_file() else ""
    if not path:
        return {}, [], "not_configured"
    list_path = Path(path)
    if not list_path.is_file():
        return {}, [f"Tor exit list: file missing: {path}"], "failed"
    try:
        mtime = list_path.stat().st_mtime
        cached = _tor_cache.get(path)
        if cached and cached[0] == mtime:
            ips = cached[1]
        else:
            ips = {
                line.strip()
                for line in list_path.read_text().splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            }
            _tor_cache[path] = (mtime, ips)
        return {"is_tor": ip in ips}, [], "active"
    except Exception as exc:
        return {}, [f"Tor exit list: {type(exc).__name__}: {exc}"], "failed"


def _stale_hours() -> int:
    """Read the configured enrichment freshness window with a safe default."""
    try:
        return max(1, int(os.getenv("STALE_HOURS", "72")))
    except ValueError:
        return 72


def _non_public_result(address: ipaddress.IPv4Address | ipaddress.IPv6Address, attempt: int) -> dict:
    """Build the stable enrichment response for non-public IP addresses."""
    fetched_at = _now()
    return {
        "ip": str(address),
        "is_private": True,
        "address_scope": _address_scope(address),
        "risk_score": 0,
        "risk_level": "not_applicable",
        "evidence": ["Non-public address"],
        "sources": [],
        "identity_evidence": ["Non-public address"],
        "field_sources": {},
        "provider_status": {},
        "fetched_at": fetched_at,
        "privacy_recheck_due_at": (datetime.fromisoformat(fetched_at) + timedelta(hours=_stale_hours())).isoformat(),
        "organization_confidence": 0,
        "reputation": [],
        "provider_errors": [],
        "enrichment_status": "complete",
        "core_enrichment_status": "complete",
        "privacy_enrichment_status": "unknown",
        "threat_enrichment_status": "unknown",
        "next_retry_at": None,
        "enrichment_attempts": attempt,
        "is_hosting": None,
        "is_vpn": None,
        "is_proxy": None,
        "proxy_type": None,
        "is_tor": None,
        "abuse_score": None,
        "abuse_reports": None,
        "network_type": "private/non-public",
        "network_location": None,
        "location_confidence": 0,
        "location_disputed": False,
        "anonymization": {"is_vpn": None, "is_proxy": None, "is_hosting": None, "is_tor": None, "confidence": 0, "sources": []},
    }


async def _resolve_global_geo(ip_text: str, refresh: bool, result: dict, field_sources: dict, errors: list[str], sources: list[str]) -> None:
    """Resolve local geo candidates and merge the canonical operational location."""
    mm = {}
    try:
        def resolve_local():
            """Read the cached PostgreSQL network mapping for one IP."""
            return resolve_network_location(ip_text, mm, force_refresh=refresh)

        geo = await asyncio.to_thread(resolve_local)
        sapics = {}
        try:
            from ..services.sapics_reader import lookup as sapics_lookup
            sapics = await asyncio.to_thread(sapics_lookup, ip_text)
        except Exception as exc:
            errors.append(f"SAPICS local resolver: {type(exc).__name__}: {exc}")
        ip2region = {}
        try:
            from ..services.ip2region_reader import lookup as ip2region_lookup
            ip2region = await asyncio.to_thread(ip2region_lookup, ip_text)
        except Exception as exc:
            errors.append(f"ip2region local resolver: {type(exc).__name__}: {exc}")

        origin_asn = sapics.get("asn", {})
        if origin_asn.get("number") is not None:
            result["asn"] = origin_asn["number"]
            field_sources["asn"] = "SAPICS origin-asn"
        if origin_asn.get("organization"):
            result["organization"] = origin_asn["organization"]
            field_sources["organization"] = "SAPICS origin-asn"

        if not (geo.get("country_code") or sapics.get("country", {}).get("value")):
            return

        normalized, registration, owner_override = _normalize_geo_candidates(geo, sapics, ip2region)
        codes = {str(record.get("country_code")).upper() for record in normalized if record.get("country_code")}
        country_bounds = await asyncio.to_thread(bounds_for, codes)
        validated = await asyncio.to_thread(validate_records, normalized, country_bounds=country_bounds)
        hierarchy = await asyncio.to_thread(_geo_hierarchy)
        resolve_kwargs = {
            "registration_context": registration,
            "evidence": [{"type": "context_validation", "source": "ip2region", "value": ip2region,
                          "role": "supporting_context_only", "confidence": None}] if ip2region else [],
        }
        if hierarchy is not None:
            resolve_kwargs["hierarchy"] = hierarchy
        canonical = resolve_geo_records(validated, **resolve_kwargs)
        _apply_geo_resolution(canonical, validated, registration, geo, sapics, ip2region,
                              owner_override, result, field_sources, sources)
    except Exception as exc:
        errors.append(f"Global geo resolver: {type(exc).__name__}: {exc}")


def _record_provider_result(name: str, data: dict, provider_errors: list[str], state: str, result: dict,
                            field_sources: dict, provider_status: dict, errors: list[str], sources: list[str]) -> None:
    """Merge one provider result and preserve its status and provenance."""
    errors.extend(provider_errors)
    _provider_state(provider_status, name, state, provider_errors[0] if provider_errors else None)
    if _merge(result, data, name, field_sources):
        sources.append(name)


def _apply_network_flag_defaults(result: dict, field_sources: dict) -> None:
    """Fill missing network flags from local organization heuristics."""
    flags = _network_flags(result.get("organization"), result.get("isp"))
    for field, value in flags.items():
        if result.get(field) is None and _present(value):
            result[field] = value
            field_sources[field] = "local heuristic"


def _finalize_lookup(result: dict, attempt: int, field_sources: dict, provider_status: dict,
                     errors: list[str], sources: list[str]) -> dict:
    """Derive final status, confidence, risk, and freshness fields."""
    _apply_network_flag_defaults(result, field_sources)
    confidence, identity_evidence = _identity_confidence(
        result.get("organization"), result.get("asn"), result.get("network_type")
    )
    core_status, privacy_status, threat_status = _enrichment_statuses(result)
    result["abuse_reputation"] = abuse_reputation_state(result.get("threat_indicators"), provider_status)

    fetched_at = _now()
    result.update({
        "organization_confidence": confidence,
        "identity_evidence": identity_evidence + errors,
        "field_sources": field_sources,
        "provider_status": provider_status,
        "sources": list(dict.fromkeys(sources)),
        "fetched_at": fetched_at,
        "privacy_recheck_due_at": (datetime.fromisoformat(fetched_at) + timedelta(hours=_stale_hours())).isoformat(),
        "provider_errors": errors,
        "core_enrichment_status": core_status,
        "privacy_enrichment_status": privacy_status,
        "threat_enrichment_status": threat_status,
        "enrichment_status": core_status,
        "next_retry_at": None,
        "enrichment_attempts": attempt,
        "network_location": result.get("network_location"),
        "location_confidence": result.get("location_confidence", 0),
        "location_disputed": result.get("location_disputed", False),
        "location_scope": result.get("location_scope"),
        "network_type_source": field_sources.get("network_type"),
        "asn_source": field_sources.get("asn"),
        "geo_sources": result.get("network_location", {}).get("sources", []),
        "geo_resolved_at": fetched_at,
        "anonymization": _anonymization_summary(result, sources),
    })
    result["risk_score"], result["risk_level"], result["evidence"] = _risk(result)
    _append_geo_configuration_warning(result, core_status, provider_status)
    return result


async def lookup(ip: str, attempt: int = 1, refresh: bool = False) -> dict:
    """Enrich an IP from local stores and datasets without network requests."""
    address = ipaddress.ip_address(ip)
    if not address.is_global:
        return _non_public_result(address, attempt)

    ip_text = str(address)
    result = {
        "ip": ip_text, "is_private": False, "address_scope": "public",
        "is_hosting": None, "is_vpn": None, "is_proxy": None, "proxy_type": None,
        "is_tor": None, "reputation": [], "abuse_score": None, "abuse_reports": None,
        "network_type": None, "ip_prefix": None,
    }
    field_sources: dict[str, str] = {}
    provider_status: dict[str, dict] = {}
    errors: list[str] = []
    sources: list[str] = []

    local, local_status, local_fields, local_errors = await asyncio.to_thread(_local_intelligence, ip_text)
    _merge(result, local, "local intelligence", field_sources)
    field_sources.update(local_fields)
    provider_status.update(local_status)
    errors.extend(local_errors)
    if local:
        sources.append("local intelligence")

    await _resolve_global_geo(ip_text, refresh, result, field_sources, errors, sources)

    maxmind, maxmind_errors, maxmind_state = await asyncio.to_thread(_maxmind, ip_text)
    _record_provider_result("MaxMind City/ASN", maxmind, maxmind_errors, maxmind_state,
                            result, field_sources, provider_status, errors, sources)
    anonymous, anonymous_errors, anonymous_state = await asyncio.to_thread(_anonymous_ip, ip_text)
    _record_provider_result("MaxMind Anonymous IP", anonymous, anonymous_errors, anonymous_state,
                            result, field_sources, provider_status, errors, sources)

    for env_name, label in (("VPN_NETWORKS_PATH", "VPN CIDR list"), ("PROXY_NETWORKS_PATH", "Proxy CIDR list")):
        matched, matched_errors, matched_state = await asyncio.to_thread(_cidr_flag, ip_text, env_name, label)
        _record_provider_result(label, matched, matched_errors, matched_state,
                                result, field_sources, provider_status, errors, sources)

    tor, tor_errors, tor_state = await asyncio.to_thread(_tor_exit_list, ip_text)
    _record_provider_result("Tor exit list", tor, tor_errors, tor_state,
                            result, field_sources, provider_status, errors, sources)
    return _finalize_lookup(result, attempt, field_sources, provider_status, errors, sources)
