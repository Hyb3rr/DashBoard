"""Small, opt-in Telegram Bot API client for security alerts."""

from __future__ import annotations

import html
import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)


def _identity_summary(profile: dict[str, Any]) -> str:
    """List active network identity flags or return the neutral fallback."""
    flags = ("Tor", "Proxy", "VPN", "Hosting")
    active = (profile.get(f"is_{name.lower()}") for name in flags)
    return ", ".join(name for name, enabled in zip(flags, active) if enabled) or "none"


def _evidence_lines(evidence: list[Any]) -> str:
    """Format a bounded list of escaped evidence lines for Telegram HTML."""
    return "\n".join(f"• {html.escape(str(item))}" for item in evidence[:8]) or "• no evidence detail"


def _score_group_text(breakdown: dict[str, Any]) -> str:
    """Render score group values in their stable display order."""
    keys = ("behavior_a", "identity_b", "trust_c", "region_d", "ai_e")
    return " / ".join(f"{key}={int(breakdown.get(key, 0) or 0)}" for key in keys)


def _reason_lines(explanations: dict[str, Any]) -> str:
    """Render escaped calculation explanations in score-group order."""
    return "\n".join(
        f"• {html.escape(str(explanations[key]))}"
        for key in ("A", "B", "C", "D", "E", "F")
        if explanations.get(key)
    )


def _recent_activity(observation: dict[str, Any]) -> str:
    """Summarize recent requests, error responses, and sensitive probes."""
    requests = int(observation.get("recent_requests", observation.get("requests", 0)) or 0)
    status_4xx = int(observation.get("recent_status_4xx", observation.get("status_4xx", 0)) or 0)
    status_5xx = int(observation.get("recent_status_5xx", observation.get("status_5xx", 0)) or 0)
    probes = int(observation.get("recent_sensitive_probe_requests", observation.get("sensitive_probe_requests", 0)) or 0)
    return f"{requests} requests, {status_4xx} 4xx, {status_5xx} 5xx, {probes} probes"


def enabled() -> bool:
    """Report whether Telegram alerts have complete enabled credentials."""
    return (
        os.getenv("TELEGRAM_ALERTS_ENABLED", "false").strip().lower()
        in {"1", "true", "yes", "on"}
        and bool(os.getenv("TELEGRAM_BOT_TOKEN", "").strip())
        and bool(os.getenv("TELEGRAM_CHAT_ID", "").strip())
    )


def cooldown_seconds() -> int:
    """Read the configured alert cooldown with a safe default."""
    try:
        return max(0, int(os.getenv("TELEGRAM_ALERT_COOLDOWN_SECONDS", "3600")))
    except ValueError:
        return 3600


def format_critical_alert(ip: str, classification: dict[str, Any], profile: dict[str, Any], observation: dict[str, Any]) -> str:
    """Format escaped classification evidence and context as a Telegram alert."""
    breakdown = classification.get("score_breakdown") or {}
    explanations = classification.get("score_explanations") or {}
    evidence = classification.get("evidence") or []
    identity = _identity_summary(profile)
    evidence_text = _evidence_lines(evidence)
    score_text = _score_group_text(breakdown)
    reasons = _reason_lines(explanations)
    score = int(classification.get("score", 0) or 0)
    confidence = int(classification.get("confidence", 0) or 0)
    return (
        f"<b>🚨 IP classified CRITICAL</b>\n"
        f"<b>IP:</b> <code>{html.escape(ip)}</code>\n"
        f"<b>Score:</b> {score}/100"
        f" · confidence {confidence}%\n"
        f"<b>Organization:</b> {html.escape(str(profile.get('organization') or 'unknown'))}\n"
        f"<b>ASN:</b> {html.escape(str(profile.get('asn') or 'unknown'))}\n"
        f"<b>Identity:</b> {html.escape(identity)}\n"
        f"<b>Recent:</b> {_recent_activity(observation)}\n"
        f"<b>Groups:</b> {html.escape(score_text)}\n\n"
        f"<b>Why:</b>\n{reasons or '• no calculation detail'}\n\n"
        f"<b>Evidence:</b>\n{evidence_text}"
    )


def format_early_alert(payload: dict[str, Any]) -> str:
    """Format a preliminary deterministic detection for Telegram delivery."""
    return (
        "PRELIMINARY SECURITY ALERT\n"
        f"IP: {payload.get('ip') or 'unknown'}\n"
        f"Rule: {payload.get('rule_id') or 'unknown'}\n"
        f"Request: {payload.get('request') or 'unknown'}\n"
        "State: preliminary"
    )


async def send_message(message: str) -> bool:
    """Send a Telegram HTML message when alert delivery is configured."""
    if not enabled():
        return False
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url, json={"chat_id": chat_id, "text": message, "parse_mode": "HTML"})
            if response.is_error:
                logger.warning(
                    "Telegram API rejected alert: status=%s body=%s",
                    response.status_code,
                    response.text[:300],
                )
                return False
        return True
    except (httpx.HTTPError, OSError) as exc:
        logger.warning("Telegram alert delivery failed: %s", type(exc).__name__)
        return False
