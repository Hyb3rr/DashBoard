import asyncio
import json
from datetime import datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path

from ..config import settings
from ..config.settings import TOR_EXIT_LIST
def connect():
    """Stub kept for test isolation monkeypatching."""
    return None


def resolve_network_location(*args, **kwargs):
    from ..db.pg_intelligence import resolve_network_location as resolve_pg
    force_refresh = kwargs.get("force_refresh", False)
    if len(args) >= 2 and isinstance(args[0], (str, ipaddress._BaseAddress)):
        return resolve_pg(str(args[0]), args[1] if len(args) > 1 else kwargs.get("vendor"), force_refresh=force_refresh)
    if len(args) >= 2:  # legacy (conn, ip, vendor) signature
        return resolve_pg(str(args[1]), args[2] if len(args) > 2 else kwargs.get("vendor"), force_refresh=force_refresh)
    if len(args) == 1:
        return resolve_pg(str(args[0]), kwargs.get("vendor"), force_refresh=force_refresh)
    return resolve_pg(kwargs.get("ip", ""), kwargs.get("vendor"), force_refresh=force_refresh)


from .net_utils import candidate_networks



try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

_reader_cache: dict[tuple[str, str], object] = {}
_tor_cache: dict[str, tuple[float, set[str]]] = {}
_cidr_cache: dict[str, tuple[float, tuple[ipaddress._BaseNetwork, ...]]] = {}


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
    if state == "not_configured":
        return
    status[name] = {"status": state, "checked_at": _now()}
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


def _anonymous_ip(ip: str) -> tuple[dict, list[str], str]:
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


def abuse_reputation_state(threat_indicators=None, provider_status=None) -> dict:
    """Derive reputation visibility without contributing to detection score."""
    sources = {
        str(item.get("source"))
        for item in (threat_indicators or [])
        if isinstance(item, dict) and item.get("source")
    }
    sources.update(
        str(source) for source in (provider_status or {})
        if str(source) in {"firehol:abuseipdb_1d", "firehol:abuseipdb_30d"}
    )
    hit_1d = "firehol:abuseipdb_1d" in sources
    hit_30d = "firehol:abuseipdb_30d" in sources
    state = "persistent" if hit_1d and hit_30d else "recent" if hit_1d else "historical" if hit_30d else "none"
    return {
        "state": state,
        "recent_hit": hit_1d,
        "history_30d_hit": hit_30d,
        "sources": [source for source in ("firehol:abuseipdb_1d", "firehol:abuseipdb_30d") if source in sources],
    }


def intel_tags_for_abuse(abuse_reputation: dict | None) -> list[str]:
    state = (abuse_reputation or {}).get("state", "none")
    return [f"intel:abuse_{state}"] if state in {"recent", "historical", "persistent"} else []


def _local_intelligence(ip: str) -> tuple[dict, dict, dict, list[str]]:
    """Read normalized intelligence snapshot from PostgreSQL."""
    from ..db.pg_intelligence import local_intelligence
    return local_intelligence(ip)

    try:
        conn = connect()
        address = ipaddress.ip_address(ip)
        candidates = candidate_networks(address)
        placeholders = ",".join("?" for _ in candidates)
        matches = conn.execute(
            f"SELECT * FROM privacy_networks WHERE active=1 AND network IN ({placeholders})",
            candidates,
        ).fetchall()
        for row in matches:
            try:
                if address not in ipaddress.ip_network(row["network"], strict=False):
                    continue
            except ValueError:
                continue
            kind, source = row["kind"], row["source"]
            field = "is_vpn" if kind == "vpn" else "is_proxy" if kind == "proxy" else "is_hosting"
            result[field] = True
            prior = fields.get(field)
            fields[field] = ", ".join(dict.fromkeys(filter(None, [prior, source])))
            providers[source] = {"status":"active", "checked_at":row["checked_at"], "kind":kind}
            if kind == "proxy" and row["proxy_type"] and not result.get("proxy_type"):
                result["proxy_type"] = row["proxy_type"]; fields["proxy_type"] = source
        threat = []
        threat_rows = conn.execute(
            f"SELECT * FROM threat_indicators WHERE active=1 AND network IN ({placeholders})",
            candidates,
        ).fetchall()
        for row in threat_rows:
            try:
                if address not in ipaddress.ip_network(row["network"], strict=False): continue
            except ValueError:
                continue
            threat.append(row)
        for row in threat:
            providers[row["source"]] = {"status":"active", "checked_at":row["checked_at"], "category":row["category"]}
            # FireHOL proxy lists are also valid local privacy evidence. Keep
            # them separate from generic threat categories, but expose the
            # proxy flag to the privacy scorer when the snapshot is present.
            if row["source"] in {"firehol:firehol_proxies", "firehol:firehol_anonymous"}:
                result["is_proxy"] = True
                fields["is_proxy"] = row["source"]
        if threat: result["threat_indicators"] = [dict(row) for row in threat]
        resolution = conn.execute("SELECT * FROM geo_resolutions WHERE ip=?", (ip,)).fetchone()
        if resolution:
            evidence = json.loads(resolution["evidence_json"] or "{}")
            result["network_location"] = {
                "country": resolution["country"],
                "country_code": resolution["country_code"],
                "city": resolution["city"],
                "latitude": resolution["latitude"],
                "longitude": resolution["longitude"],
                "confidence": resolution["confidence"],
                "disputed": bool(resolution["disputed"]),
                "scope": resolution["location_scope"],
                "sources": json.loads(resolution["source_ids_json"] or "[]"),
                "confidence_breakdown": evidence.get("confidence_breakdown", {}),
                # `country`/`country_code` above are the *operational* location.
                # `registration` is separate RIR/WHOIS ownership context and is
                # expected to differ for global cloud/CDN networks - see
                # allocation_pattern for whether that's the normal case.
                "registration": evidence.get("registration"),
                "allocation_pattern": evidence.get("allocation_pattern", "unknown"),
                "volatile_location": evidence.get("volatile_location", False),
            }
            result.update({key: resolution[key] for key in ("asn", "organization", "network_type", "latitude", "longitude", "city") if resolution[key]})
            providers["geo_resolution"] = {"status": "active", "checked_at": resolution["resolved_at"]}
        conn.close()
    except Exception as exc:
        errors.append(f"Local intelligence: {type(exc).__name__}: {exc}")
    return result, providers, fields, errors


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


async def lookup(ip: str, attempt: int = 1, refresh: bool = False) -> dict:
    """Local-only IP enrichment.

    No HTTP requests, DNS lookups, Tor downloads or reputation APIs are used.
    Priority is map data first: country/country_code/latitude/longitude.
    """
    address = ipaddress.ip_address(ip)
    if not address.is_global:
        fetched_at = _now()
        try:
            stale_hours = max(1, int(os.getenv("STALE_HOURS", "72")))
        except ValueError:
            stale_hours = 72
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
            "fetched_at": fetched_at,
            "privacy_recheck_due_at": (datetime.fromisoformat(fetched_at) + timedelta(hours=stale_hours)).isoformat(),
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

    ip_text = str(address)
    result = {
        "ip": ip_text,
        "is_private": False,
        "is_hosting": None,
        "is_vpn": None,
        "is_proxy": None,
        "proxy_type": None,
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

    local, local_status, local_fields, local_errors = await asyncio.to_thread(_local_intelligence, ip_text)
    _merge(result, local, "local intelligence", field_sources)
    field_sources.update(local_fields)
    provider_status.update(local_status)
    errors.extend(local_errors)
    if local:
        sources.append("local intelligence")

    # 1) SAPICS local MMDB layer owns Geo/ASN data. No provider API or direct
    # MaxMind/DB-IP download is used here.
    # The _maxmind and _tor_exit_list calls are synchronous, blocking
    # disk/mmap reads. Running each one via asyncio.to_thread means the event
    # loop is free while the read happens, so when the caller (main.py) fires
    # off several lookup(ip) coroutines at once with asyncio.gather, the actual
    # file reads for *different IPs* genuinely overlap on OS threads instead of
    # running one-IP-at-a-time. Reader objects are still cached/reused (see
    # _reader_cache) so this doesn't reopen the mmap per call.
    mm = {}

    # Prefix and ASN resolution is local-only. The updater populates the
    # snapshots; this fallback lets MaxMind remain useful before the first
    # global snapshot has been built.
    try:
        def resolve_local():
            return resolve_network_location(None, ip_text, mm, force_refresh=refresh)


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
        if geo.get("country_code") or sapics.get("country", {}).get("value"):
            owner_override = any("geofeed" in str(source).lower() or "cloud" in str(source).lower()
                                 for source in geo.get("sources", []))
            sap_country = sapics.get("country", {})
            sap_city = sapics.get("city", {})
            selected_country = geo.get("country") if owner_override else (sap_country.get("value") or geo.get("country"))
            selected_code = geo.get("country_code") if owner_override else (sap_country.get("value") or geo.get("country_code"))
            selected_city = sap_city.get("value") or geo.get("city")
            selected_lat = sap_city.get("latitude") if sap_city.get("latitude") is not None else geo.get("latitude")
            selected_lon = sap_city.get("longitude") if sap_city.get("longitude") is not None else geo.get("longitude")
            result["network_location"] = {
                "country": selected_country,
                "country_code": selected_code,
                "city": selected_city,
                "latitude": selected_lat,
                "longitude": selected_lon,
                "confidence": geo.get("confidence", 0),
                "disputed": bool(geo.get("disputed")),
                "scope": geo.get("scope", "network") if owner_override else "sapics",
                "sources": geo.get("sources", []) if owner_override else [
                    "sapics:user-country", "sapics:server-country", "sapics:geolite2", "sapics:dbip", "sapics:origin-asn"
                ],
                "confidence_breakdown": geo.get("confidence_breakdown", {}),
                # See db-backed branch above: registration (RIR/WHOIS) is kept
                # separate from operational country and is not itself a
                # dispute signal - check allocation_pattern instead.
                "registration": geo.get("registration"),
                "allocation_pattern": geo.get("allocation_pattern", "unknown"),
                "volatile_location": geo.get("volatile_location", False),
                "geo": sapics,
                "ip2region": ip2region,
                "country_conflict": bool(sap_country.get("conflict")),
                "country_conflict_severity": sap_country.get("conflict_severity", "none"),
                "city_conflict": bool(sap_city.get("conflict")),
                "city_conflict_severity": sap_city.get("conflict_severity", "none"),
                "coordinate_conflict": bool(sap_city.get("conflict")),
                "cross_region_infrastructure": sapics.get("infrastructure", {}).get("cross_region", False),
            }
            for field, value in (("country", selected_country), ("country_code", selected_code),
                                 ("city", selected_city), ("latitude", selected_lat), ("longitude", selected_lon)):
                if value is not None:
                    result[field] = value
                    field_sources[field] = "SAPICS" if not owner_override else "owner-declared + SAPICS"
            origin_asn = sapics.get("asn", {})
            if origin_asn.get("number") is not None:
                result["asn"] = origin_asn["number"]
                field_sources["asn"] = "SAPICS origin-asn"
            if origin_asn.get("organization"):
                result["organization"] = origin_asn["organization"]
                field_sources["organization"] = "SAPICS origin-asn"
            for field in ("ip_prefix", "network_type"):
                if geo.get(field) is not None:
                    result[field] = geo[field]
                    field_sources[field] = ", ".join(geo.get("sources", [])) or "geo resolver"
            result["location_confidence"] = geo.get("confidence", 0)
            result["location_disputed"] = bool(geo.get("disputed"))
            result["location_scope"] = geo.get("scope", "network")
            sources.append("global geo resolver")
    except Exception as exc:
        errors.append(f"Global geo resolver: {type(exc).__name__}: {exc}")

    # 2) MaxMind City/ASN is a local fallback when the local resolver has no
    # mapping. It never overrides SAPICS/global-geo fields selected above.
    maxmind, maxmind_errors, maxmind_state = await asyncio.to_thread(_maxmind, ip_text)
    errors.extend(maxmind_errors)
    _provider_state(provider_status, "MaxMind City/ASN", maxmind_state, maxmind_errors[0] if maxmind_errors else None)
    if _merge(result, maxmind, "MaxMind City/ASN", field_sources):
        sources.append("MaxMind City/ASN")

    # 3) Optional MaxMind Anonymous IP database provides real VPN/proxy flags.
    anonymous, anonymous_errors, anonymous_state = await asyncio.to_thread(_anonymous_ip, ip_text)
    errors.extend(anonymous_errors)
    _provider_state(provider_status, "MaxMind Anonymous IP", anonymous_state, anonymous_errors[0] if anonymous_errors else None)
    if _merge(result, anonymous, "MaxMind Anonymous IP", field_sources):
        sources.append("MaxMind Anonymous IP")

    # 4) Optional local CIDR lists are explicit, auditable VPN/proxy sources.
    for env_name, label in (("VPN_NETWORKS_PATH", "VPN CIDR list"), ("PROXY_NETWORKS_PATH", "Proxy CIDR list")):
        matched, matched_errors, matched_state = await asyncio.to_thread(_cidr_flag, ip_text, env_name, label)
        errors.extend(matched_errors)
        _provider_state(provider_status, label, matched_state, matched_errors[0] if matched_errors else None)
        if _merge(result, matched, label, field_sources):
            sources.append(label)

    # 5) Tor remains a separate local privacy source.
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
    if any(result.get(f) is True for f in ("is_vpn", "is_proxy", "is_hosting")):
        privacy_status = "partial" if privacy_status == "unknown" else privacy_status
    threat_status = "complete" if any(k == "threat_indicators" for k in result) else "unknown"
    result["abuse_reputation"] = abuse_reputation_state(
        result.get("threat_indicators"), provider_status
    )

    fetched_at = _now()
    try:
        stale_hours = max(1, int(os.getenv("STALE_HOURS", "72")))
    except ValueError:
        stale_hours = 72
    result.update({
        "organization_confidence": confidence,
        "identity_evidence": identity_evidence + errors,
        "field_sources": field_sources,
        "provider_status": provider_status,
        "sources": list(dict.fromkeys(sources)),
        "fetched_at": fetched_at,
        "privacy_recheck_due_at": (datetime.fromisoformat(fetched_at) + timedelta(hours=stale_hours)).isoformat(),
        "provider_errors": errors,
        "core_enrichment_status": core_status,
        "privacy_enrichment_status": privacy_status,
        "threat_enrichment_status": threat_status,
        "enrichment_status": core_status,
        "next_retry_at": None,  # local-only pass does not schedule online retries
        "enrichment_attempts": attempt,
        "network_location": result.get("network_location"),
        "location_confidence": result.get("location_confidence", 0),
        "location_disputed": result.get("location_disputed", False),
        "location_scope": result.get("location_scope"),
        "network_type_source": field_sources.get("network_type"),
        "asn_source": field_sources.get("asn"),
        "geo_sources": result.get("network_location", {}).get("sources", []),
        "geo_resolved_at": fetched_at,
        "anonymization": {
            "is_vpn": result.get("is_vpn"),
            "is_proxy": result.get("is_proxy"),
            "is_hosting": result.get("is_hosting"),
            "is_tor": result.get("is_tor"),
            "confidence": max(
                (80 if result.get("is_tor") is not None else 0),
                (70 if result.get("is_vpn") is not None or result.get("is_proxy") is not None else 0),
                (60 if result.get("is_hosting") is not None else 0),
            ),
            "sources": [name for name in sources if "MaxMind Anonymous" in name or "Tor" in name or "local intelligence" in name or "VPN" in name or "Proxy" in name],
        },
    })
    result["risk_score"], result["risk_level"], result["evidence"] = _risk(result)

    geo_provider_active = any(
        provider_status.get(name, {}).get("status") in {"active", "partial"}
        for name in ("MaxMind City/ASN",)
    )
    if core_status == "failed" and not geo_provider_active:
        result["provider_errors"].append(
            "No local GeoIP database configured. Run SAPICS release updater or configure MaxMind City/ASN."
        )

    return result
