"""Pure policy helpers for interpreting local IP intelligence."""


def network_flags(organization: str | None, isp: str | None) -> dict:
    """Infer hosting context from organization labels without remote lookups."""
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


def identity_confidence(organization: str | None, asn: str | int | None,
                        network_type: str | None) -> tuple[int, list[str]]:
    """Estimate confidence in network-owner identity from local fields."""
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


def risk(data: dict) -> tuple[int, str, list[str]]:
    """Score local privacy and hosting signals without online reputation lookups."""
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
    """Build the display tag for a non-empty abuse reputation state."""
    state = (abuse_reputation or {}).get("state", "none")
    return [f"intel:abuse_{state}"] if state in {"recent", "historical", "persistent"} else []


def status_from_fields(fields: tuple[str, ...], result: dict) -> str:
    """Summarize whether required enrichment fields are present."""
    present = sum(1 for field in fields if result.get(field) is not None and result.get(field) != "")
    if present == 0:
        return "failed"
    if present == len(fields):
        return "complete"
    return "partial"


def enrichment_statuses(result: dict) -> tuple[str, str, str]:
    """Return core, privacy, and threat enrichment completeness states."""
    core = status_from_fields(("country", "country_code", "latitude", "longitude"), result)
    privacy_fields = ("is_vpn", "is_proxy", "is_hosting", "is_tor")
    privacy = "complete" if all(result.get(field) is not None for field in privacy_fields) else "unknown"
    if privacy == "unknown" and any(
        result.get(field) is True for field in ("is_vpn", "is_proxy", "is_hosting")
    ):
        privacy = "partial"
    threat = "complete" if "threat_indicators" in result else "unknown"
    return core, privacy, threat


def anonymization_summary(result: dict, sources: list[str]) -> dict:
    """Build the privacy-signal summary and its source confidence."""
    confidence = max(
        (80 if result.get("is_tor") is not None else 0),
        (70 if result.get("is_vpn") is not None or result.get("is_proxy") is not None else 0),
        (60 if result.get("is_hosting") is not None else 0),
    )
    source_markers = ("MaxMind Anonymous", "Tor", "local intelligence", "VPN", "Proxy")
    return {
        "is_vpn": result.get("is_vpn"),
        "is_proxy": result.get("is_proxy"),
        "is_hosting": result.get("is_hosting"),
        "is_tor": result.get("is_tor"),
        "confidence": confidence,
        "sources": [name for name in sources if any(marker in name for marker in source_markers)],
    }


def append_geo_configuration_warning(result: dict, core_status: str, provider_status: dict) -> None:
    """Explain missing local GeoIP setup when all core location fields failed."""
    geo_provider_active = provider_status.get("MaxMind City/ASN", {}).get("status") in {"active", "partial"}
    if core_status == "failed" and not geo_provider_active:
        result["provider_errors"].append(
            "No local GeoIP database configured. Run SAPICS release updater or configure MaxMind City/ASN."
        )
