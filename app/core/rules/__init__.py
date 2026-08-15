"""Independent, auditable web behavior detections."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class BehaviorContext:
    requests_1h: int = 0
    requests_24h: int = 0
    peak_requests_1m: int | None = None
    peak_requests_5m: int | None = None
    status_4xx_ratio_1h: float = 0.0
    unique_paths_1h: int = 0
    sensitive_probes_1h: int = 0
    first_seen: str | None = None
    last_seen: str | None = None
    requests: int = 0
    status_4xx: int = 0
    unique_paths: int = 0
    wp_login_requests: int = 0
    sensitive_probe_requests: int = 0
    bot_requests: int = 0
    status_2xx: int = 0
    status_3xx: int = 0
    status_5xx: int = 0


@dataclass(frozen=True)
class Detection:
    id: str
    name: str
    severity: str
    mitre_technique: str | None
    points: int
    evidence: str

    def to_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "severity": self.severity,
            "mitre_technique": self.mitre_technique, "points": self.points,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    mitre_technique: str | None
    points: int
    evaluate: Callable[[BehaviorContext], Detection | None]


def _rule(rule: Rule, predicate: Callable[[BehaviorContext], bool], evidence: str) -> Rule:
    return Rule(rule.id, rule.name, rule.severity, rule.mitre_technique, rule.points,
                lambda ctx: Detection(rule.id, rule.name, rule.severity, rule.mitre_technique, rule.points, evidence) if predicate(ctx) else None)


RULES = [
    _rule(Rule("WEB-SENSITIVE-001", "Sensitive path probing", "high", "T1190", 50, None), lambda c: c.sensitive_probe_requests > 0, "Sensitive path probing (+50)"),
    _rule(Rule("WEB-BRUTE-001", "WordPress login burst", "high", "T1110", 30, ""), lambda c: c.wp_login_requests > 20, "wp-login burst (+30)"),
    _rule(Rule("WEB-4XX-001", "Repeated client errors", "medium", "T1190", 15, ""), lambda c: c.requests >= 20 and c.status_4xx / c.requests > 0.5, "4xx ratio above 50% (+15)"),
    _rule(Rule("WEB-SCAN-001", "High path cardinality", "medium", "T1595", 15, ""), lambda c: c.unique_paths > 80, "High unique path count (+15)"),
    _rule(Rule("WEB-BOT-001", "Bot repeated errors", "low", "T1583", 10, ""), lambda c: bool(c.bot_requests) and c.status_4xx > 10, "Bot with repeated errors"),
    _rule(Rule("WEB-RATE-001", "Sustained request rate", "medium", "T1498", 10, ""), lambda c: c.peak_requests_5m is not None and c.peak_requests_5m >= 100, "Sustained rate above 100 requests/5m (+10)"),
    _rule(Rule("WEB-BURST-001", "Minute request burst", "high", "T1498", 20, ""), lambda c: c.peak_requests_1m is not None and c.peak_requests_1m >= 100, "Burst above 100 requests/min (+20)"),
]


def run_rules(ctx: BehaviorContext) -> list[Detection]:
    return [detection for rule in RULES if (detection := rule.evaluate(ctx)) is not None]
