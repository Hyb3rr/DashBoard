"""Safe, YAML-backed behavior rule registry."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any

import yaml


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
    rule_version: int = 1
    rule_type: str = "anomaly"

    def to_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "severity": self.severity,
            "mitre_technique": self.mitre_technique, "points": self.points,
            "evidence": self.evidence, "rule_version": self.rule_version,
            "rule_type": self.rule_type,
        }


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    mitre_technique: str | None
    points: int
    condition: dict
    description: str
    version: int
    rule_type: str


DEFAULT_RULES_DIR = Path(__file__).resolve().parents[3] / "rules"
_registry: tuple[Rule, ...] = ()
_ruleset_hash = ""


def _validate_rule(raw: Any, filename: str) -> Rule:
    if not isinstance(raw, dict):
        raise ValueError(f"{filename}: rule must be a mapping")
    required = ("id", "name", "severity", "points", "rule_type", "window", "condition", "version", "enabled")
    missing = [field for field in required if field not in raw]
    if missing:
        raise ValueError(f"{filename}: missing fields {', '.join(missing)}")
    if not raw["enabled"]:
        raise ValueError(f"{filename}: disabled rules must not be loaded")
    rule_type = str(raw["rule_type"])
    mitre = raw.get("mitre_technique")
    if rule_type == "technique" and not mitre:
        raise ValueError(f"{filename}: technique rule requires mitre_technique")
    if rule_type == "anomaly" and mitre is not None:
        raise ValueError(f"{filename}: anomaly rule must not declare mitre_technique")
    if not isinstance(raw["condition"], dict):
        raise ValueError(f"{filename}: condition must be a mapping")
    return Rule(str(raw["id"]), str(raw["name"]), str(raw["severity"]), mitre,
                int(raw["points"]), raw["condition"], str(raw.get("description", "")),
                int(raw["version"]), rule_type)


def load_rules(path: Path | None = None) -> tuple[tuple[Rule, ...], str]:
    directory = path or DEFAULT_RULES_DIR
    rules: list[Rule] = []
    serialized: list[dict] = []
    for filename in sorted(directory.glob("*.yaml")):
        raw = yaml.safe_load(filename.read_text(encoding="utf-8"))
        rule = _validate_rule(raw, str(filename))
        if any(existing.id == rule.id for existing in rules):
            raise ValueError(f"{filename}: duplicate rule id {rule.id}")
        rules.append(rule)
        serialized.append(raw)
    if not rules:
        raise ValueError(f"{directory}: no enabled rule files found")
    digest = hashlib.sha256(json.dumps(serialized, sort_keys=True).encode()).hexdigest()
    return tuple(rules), digest


def reload_rules(path: Path | None = None) -> str:
    global _registry, _ruleset_hash
    rules, digest = load_rules(path)
    _registry = rules
    _ruleset_hash = digest
    return digest


def ruleset_hash() -> str:
    global _registry, _ruleset_hash
    if not _registry:
        reload_rules()
    return _ruleset_hash


def rules() -> tuple[Rule, ...]:
    if not _registry:
        reload_rules()
    return _registry


def _field(ctx: BehaviorContext, name: str) -> Any:
    if name == "status_4xx_ratio":
        return ctx.status_4xx / ctx.requests if ctx.requests else 0.0
    if name == "status_4xx_ratio_1h":
        return ctx.status_4xx_ratio_1h
    if name == "requests_1h":
        return ctx.requests_1h
    if name == "requests_24h":
        return ctx.requests_24h
    if not hasattr(ctx, name):
        raise ValueError(f"unsupported condition field: {name}")
    return getattr(ctx, name)


def _compare(actual: Any, operator: str, expected: Any) -> bool:
    if actual is None and operator in {"gt", "gte", "lt", "lte"}:
        actual = 0
    if operator == "eq": return actual == expected
    if operator == "ne": return actual != expected
    if operator == "gt": return actual > expected
    if operator == "gte": return actual >= expected
    if operator == "lt": return actual < expected
    if operator == "lte": return actual <= expected
    if operator == "in": return actual in expected
    if operator == "contains": return expected in actual
    raise ValueError(f"unsupported condition operator: {operator}")


def evaluate_condition(ctx: BehaviorContext, node: dict) -> bool:
    if "all" in node:
        return all(evaluate_condition(ctx, child) for child in node["all"])
    if "any" in node:
        return any(evaluate_condition(ctx, child) for child in node["any"])
    if "not" in node:
        return not evaluate_condition(ctx, node["not"])
    if not {"field", "operator", "value"}.issubset(node):
        raise ValueError("condition leaf requires field, operator and value")
    return _compare(_field(ctx, str(node["field"])), str(node["operator"]), node["value"])


def run_rules(ctx: BehaviorContext) -> list[Detection]:
    result = []
    for rule in rules():
        if evaluate_condition(ctx, rule.condition):
            result.append(Detection(rule.id, rule.name, rule.severity, rule.mitre_technique,
                                    rule.points, f"{rule.description} (+{rule.points})",
                                    rule.version, rule.rule_type))
    return result
