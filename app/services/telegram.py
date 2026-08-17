"""Small, opt-in Telegram Bot API client for security alerts."""

from __future__ import annotations

import html
import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)


def enabled() -> bool:
    return (
        os.getenv("TELEGRAM_ALERTS_ENABLED", "false").strip().lower()
        in {"1", "true", "yes", "on"}
        and bool(os.getenv("TELEGRAM_BOT_TOKEN", "").strip())
        and bool(os.getenv("TELEGRAM_CHAT_ID", "").strip())
    )


def cooldown_seconds() -> int:
    try:
        return max(0, int(os.getenv("TELEGRAM_ALERT_COOLDOWN_SECONDS", "3600")))
    except ValueError:
        return 3600


def format_bad_alert(ip: str, classification: dict[str, Any], profile: dict[str, Any], observation: dict[str, Any]) -> str:
    breakdown = classification.get("score_breakdown") or {}
    explanations = classification.get("score_explanations") or {}
    evidence = classification.get("evidence") or []
    identity = ", ".join(
        name for name, active in (("Tor", profile.get("is_tor")), ("Proxy", profile.get("is_proxy")),
                                  ("VPN", profile.get("is_vpn")), ("Hosting", profile.get("is_hosting")))
        if active
    ) or "none"
    evidence_text = "\n".join(f"• {html.escape(str(item))}" for item in evidence[:8]) or "• no evidence detail"
    score_text = " / ".join(
        f"{key}={int(breakdown.get(key, 0) or 0)}"
        for key in ("behavior_a", "identity_b", "trust_c", "region_d", "ai_e")
    )
    reasons = "\n".join(
        f"• {html.escape(str(explanations[key]))}"
        for key in ("A", "B", "C", "D", "E", "F")
        if explanations.get(key)
    )
    return (
        f"<b>🚨 IP classified BAD</b>\n"
        f"<b>IP:</b> <code>{html.escape(ip)}</code>\n"
        f"<b>Score:</b> {int(classification.get('score', 0) or 0)}/100"
        f" · confidence {int(classification.get('confidence', 0) or 0)}%\n"
        f"<b>Organization:</b> {html.escape(str(profile.get('organization') or 'unknown'))}\n"
        f"<b>ASN:</b> {html.escape(str(profile.get('asn') or 'unknown'))}\n"
        f"<b>Identity:</b> {html.escape(identity)}\n"
        f"<b>Recent:</b> {int(observation.get('recent_requests', observation.get('requests', 0)) or 0)} requests, "
        f"{int(observation.get('recent_status_4xx', observation.get('status_4xx', 0)) or 0)} 4xx, "
        f"{int(observation.get('recent_status_5xx', observation.get('status_5xx', 0)) or 0)} 5xx, "
        f"{int(observation.get('recent_sensitive_probe_requests', observation.get('sensitive_probe_requests', 0)) or 0)} probes\n"
        f"<b>Groups:</b> {html.escape(score_text)}\n\n"
        f"<b>Why:</b>\n{reasons or '• no calculation detail'}\n\n"
        f"<b>Evidence:</b>\n{evidence_text}"
    )


async def send_message(message: str) -> bool:
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
