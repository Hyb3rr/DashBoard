import asyncio
from datetime import datetime, timezone
import ipaddress
import os
from pathlib import Path

from ..config.settings import TOR_EXIT_LIST

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

_reader_cache: dict[tuple[str, str], object] = {}
_tor_cache: dict[str, tuple[float, set[str]]] = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _present(value) -> bool:
    return value is not None and value != ""


def _reader(kind: str, path: str, factory):
    key = (kind, path)
    cached = _reader_cache.get(key)
    if cached is None:
        cached = factory(path)
        _reader_cache[key] = cached
    return cached


def _merge(base: dict, incoming: dict, provider: str, field_sources: dict) -> list[str]:
    filled = []
    for field, value in incoming.items():
        if _present(value) and not _present(base.get(field)):
            base[field] = value
            field_sources[field] = provider
            filled.append(field)
    return filled


def _provider_state(status: dict, name: str, state: str, error: str | None = None) -> None:
    status[name] = {"status": state}
    if error:
        status[name]["error"] = error


def _status_from_fields(fields: tuple[str, ...], result: dict) -> str:
    present = sum(1 for field in fields if _present(result.get(field)))
    if present == 0:
        return "failed"
    if present == len(fields):
        return "complete"
    return "partial"


def _network_flags(organization: str | None, isp: str | None) -> dict:
    text = f"{organization or ''} {isp or ''}".lower()
    hosting_words = ("hosting", "cloud", "data center", "datacenter", "server", "vps", "compute")
    cdn_words = ("cloudflare", "akamai", "fastly", "cdn")
    is_hosting = any(word in text for word in hosting_words)
    if any(word in text for word in cdn_words):
        network_type = "cdn"
    elif is_hosting:
        network_type = "hosting/datacenter"
    elif text.strip():
        network_type = "isp/unknown"
    else:
        network_type = "unknown"
    return {
        "is_hosting": is_hosting if text.strip() else None,
        "is_vpn": None,
        "is_proxy": None,
        "network_type": network_type,
    }


def _identity_confidence(organization: str | None, asn: str | int | None, network_type: str | None) -> tuple[int, list[str]]:
    evidence = []
    if organization:
        evidence.append("Organization from local network database")
    if asn:
        evidence.append("ASN present")
    if network_type:
        evidence.append(f"Network type: {network_type}")
    if not organization:
        return 0, ["No organization signal in local databases"]
    if network_type in ("hosting/datacenter", "cdn"):
        return 80, evidence + ["Likely network owner, not visitor identity"]
    if asn:
        return 70, evidence + ["Network owner confidence only"]
    return 45, evidence + ["Weak organization signal"]


def _risk(data: dict) -> tuple[int, str, list[str]]:
    # Local-only risk. No online reputation lookup is performed here.
    score, evidence = 0, []
    for field, points, label in (
        ("is_tor", 55, "Tor exit node signal"),
        ("is_proxy", 35, "Proxy signal from local database"),
        ("is_vpn", 30, "VPN signal from local database"),
        ("is_hosting", 20, "Hosting/datacenter signal"),
    ):
        if data.get(field):
            score += points
            evidence.append(label)
    score = min(score, 100)
    level = "low" if score < 25 else "medium" if score < 55 else "high" if score < 80 else "critical"
    return score, level, evidence


def _maxmind(ip: str) -> tuple[dict, list[str], str]:
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


async def lookup(ip: str, attempt: int = 1) -> dict:
    """Local-only IP enrichment.

    No HTTP requests, DNS lookups, Tor downloads or reputation APIs are used.
    Priority is map data first: country/country_code/latitude/longitude.
    """
    address = ipaddress.ip_address(ip)
    if not address.is_global:
        return {
            "ip": str(address),
            "is_private": True,
            "risk_score": 0,
            "risk_level": "not_applicable",
            "evidence": ["Non-public address"],
            "sources": [],
            "identity_evidence": ["Non-public address"],
            "field_sources": {},
            "provider_status": {},
            "fetched_at": _now(),
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
            "is_tor": None,
            "abuse_score": None,
            "abuse_reports": None,
            "network_type": "private/non-public",
        }

    ip_text = str(address)
    result = {
        "ip": ip_text,
        "is_private": False,
        "is_hosting": None,
        "is_vpn": None,
        "is_proxy": None,
        "is_tor": None,
        "reputation": [],
        "abuse_score": None,
        "abuse_reports": None,
        "network_type": None,
        "ip_prefix": None,
    }
    field_sources: dict[str, str] = {}
    provider_status: dict[str, dict] = {}
    errors: list[str] = []
    sources: list[str] = []

    # 1) MaxMind local first.
    # The _maxmind and _tor_exit_list calls are synchronous, blocking
    # disk/mmap reads. Running each one via asyncio.to_thread means the event
    # loop is free while the read happens, so when the caller (main.py) fires
    # off several lookup(ip) coroutines at once with asyncio.gather, the actual
    # file reads for *different IPs* genuinely overlap on OS threads instead of
    # running one-IP-at-a-time. Reader objects are still cached/reused (see
    # _reader_cache) so this doesn't reopen the mmap per call.
    mm, mm_errors, mm_state = await asyncio.to_thread(_maxmind, ip_text)
    errors.extend(mm_errors)
    _provider_state(provider_status, "MaxMind City/ASN", mm_state, mm_errors[0] if mm_errors else None)
    if _merge(result, mm, "MaxMind", field_sources):
        sources.append("MaxMind")

    # 2) Tor is the only local privacy source currently enabled.
    tor, tor_errors, tor_state = await asyncio.to_thread(_tor_exit_list, ip_text)
    errors.extend(tor_errors)
    _provider_state(provider_status, "Tor exit list", tor_state, tor_errors[0] if tor_errors else None)
    if _merge(result, tor, "Tor exit list", field_sources):
        sources.append("Tor exit list")

    flags = _network_flags(result.get("organization"), result.get("isp"))
    for field, value in flags.items():
        if result.get(field) is None and _present(value):
            result[field] = value
            field_sources[field] = "local heuristic"

    confidence, identity_evidence = _identity_confidence(
        result.get("organization"), result.get("asn"), result.get("network_type")
    )

    # Mapping completion requires only the fields necessary to put a point on a map.
    core_status = _status_from_fields(
        ("country", "country_code", "latitude", "longitude"), result
    )

    privacy_fields = ("is_vpn", "is_proxy", "is_hosting", "is_tor")
    privacy_status = "complete" if all(result.get(f) is not None for f in privacy_fields) else "unknown"

    result.update({
        "organization_confidence": confidence,
        "identity_evidence": identity_evidence + errors,
        "field_sources": field_sources,
        "provider_status": provider_status,
        "sources": list(dict.fromkeys(sources)),
        "fetched_at": _now(),
        "provider_errors": errors,
        "core_enrichment_status": core_status,
        "privacy_enrichment_status": privacy_status,
        "threat_enrichment_status": "unknown",
        "enrichment_status": core_status,
        "next_retry_at": None,  # local-only pass does not schedule online retries
        "enrichment_attempts": attempt,
    })
    result["risk_score"], result["risk_level"], result["evidence"] = _risk(result)

    geo_provider_active = any(
        provider_status.get(name, {}).get("status") in {"active", "partial"}
        for name in ("MaxMind City/ASN",)
    )
    if core_status == "failed" and not geo_provider_active and not errors:
        result["provider_errors"].append(
            "No local GeoIP database configured. Set MAXMIND_CITY_DB and/or MAXMIND_ASN_DB."
        )

    return result
