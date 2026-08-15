"""Safe, YAML-backed behavior rule registry."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import time
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
    window: str
    false_positive_notes: tuple[str, ...]


DEFAULT_RULES_DIR = Path(__file__).resolve().parents[3] / "rules"
_registry: tuple[Rule, ...] = ()
_ruleset_hash = ""
_rules_path: Path = DEFAULT_RULES_DIR
_rules_signature: tuple[tuple[str, int, int], ...] = ()
_health = {"status": "unloaded", "error": None, "loaded_at": None, "ruleset_hash": None, "rule_count": 0}


def _validate_rule(raw: Any, filename: str) -> Rule:
    if not isinstance(raw, dict):
        raise ValueError(f"{filename}: rule must be a mapping")
    required = ("id", "name", "severity", "points", "rule_type", "window", "condition", "version", "enabled", "false_positive_notes")
    missing = [field for field in required if field not in raw]
    if missing:
        raise ValueError(f"{filename}: missing fields {', '.join(missing)}")
    if not isinstance(raw["enabled"], bool):
        raise ValueError(f"{filename}: enabled must be boolean")
    if not raw["enabled"]:
        return None
    if not re.fullmatch(r"[A-Z][A-Z0-9-]{2,63}", str(raw["id"])):
        raise ValueError(f"{filename}: invalid rule id")
    if not isinstance(raw["version"], int) or raw["version"] < 1:
        raise ValueError(f"{filename}: version must be a positive integer")
    if str(raw["severity"]) not in {"low", "medium", "high", "critical"}:
        raise ValueError(f"{filename}: invalid severity")
    if not isinstance(raw["points"], int) or not 0 <= raw["points"] <= 100:
        raise ValueError(f"{filename}: points must be an integer from 0 to 100")
    if str(raw["window"]) not in {"1h", "24h"}:
        raise ValueError(f"{filename}: window must be 1h or 24h")
    if not isinstance(raw["false_positive_notes"], list) or not raw["false_positive_notes"]:
        raise ValueError(f"{filename}: false_positive_notes must be a non-empty list")
    rule_type = str(raw["rule_type"])
    mitre = raw.get("mitre_technique")
    if rule_type == "technique" and not mitre:
        raise ValueError(f"{filename}: technique rule requires mitre_technique")
    if mitre is not None and not re.fullmatch(r"T\d{4}(?:\.\d{3})?", str(mitre)):
        raise ValueError(f"{filename}: invalid mitre_technique")
    _validate_condition(raw["condition"], filename, 0)
    return Rule(str(raw["id"]), str(raw["name"]), str(raw["severity"]), mitre,
                int(raw["points"]), raw["condition"], str(raw.get("description", "")),
                int(raw["version"]), rule_type, str(raw["window"]), tuple(str(item) for item in raw["false_positive_notes"]))


_FIELDS = {
    "requests", "requests_1h", "requests_24h", "status_2xx", "status_3xx", "status_4xx",
    "status_5xx", "status_4xx_ratio", "status_4xx_ratio_1h", "unique_paths", "unique_paths_1h",
    "wp_login_requests", "sensitive_probe_requests", "sensitive_probes_1h", "bot_requests",
    "peak_requests_1m", "peak_requests_5m",
}
_OPERATORS = {"eq", "ne", "gt", "gte", "lt", "lte", "in", "contains"}


def _validate_condition(node: Any, filename: str, depth: int) -> None:
    if depth > 12 or not isinstance(node, dict):
        raise ValueError(f"{filename}: invalid condition tree")
    keys = set(node)
    logical = keys & {"all", "any", "not"}
    if logical:
        if len(logical) != 1 or keys != logical:
            raise ValueError(f"{filename}: invalid logical condition")
        key = next(iter(logical))
        children = node[key] if key != "not" else [node[key]]
        if not isinstance(children, list) or not children:
            raise ValueError(f"{filename}: logical condition requires children")
        for child in children:
            _validate_condition(child, filename, depth + 1)
        return
    if keys != {"field", "operator", "value"}:
        raise ValueError(f"{filename}: invalid condition leaf")
    if node["field"] not in _FIELDS:
        raise ValueError(f"{filename}: unsupported condition field {node['field']}")
    if node["operator"] not in _OPERATORS:
        raise ValueError(f"{filename}: unsupported condition operator {node['operator']}")


def load_rules(path: Path | None = None) -> tuple[tuple[Rule, ...], str]:
    directory = path or DEFAULT_RULES_DIR
    rules: list[Rule] = []
    serialized: list[dict] = []
    for filename in sorted(directory.glob("*.yaml")):
        raw = yaml.safe_load(filename.read_text(encoding="utf-8"))
        rule = _validate_rule(raw, str(filename))
        if rule is None:
            continue
        if any(existing.id == rule.id for existing in rules):
            raise ValueError(f"{filename}: duplicate rule id {rule.id}")
        rules.append(rule)
        serialized.append(raw)
    if not rules:
        raise ValueError(f"{directory}: no enabled rule files found")
    digest = hashlib.sha256(json.dumps(serialized, sort_keys=True).encode()).hexdigest()
    return tuple(rules), digest


def reload_rules(path: Path | None = None) -> str:
    global _registry, _ruleset_hash, _rules_path, _rules_signature, _health
    directory = path or _rules_path
    rules, digest = load_rules(directory)
    signature = _signature(directory)
    _registry = rules
    _ruleset_hash = digest
    _rules_path = directory
    _rules_signature = signature
    _health = {"status": "ok", "error": None, "loaded_at": time.time(), "ruleset_hash": digest, "rule_count": len(rules)}
    return digest


def _signature(directory: Path) -> tuple[tuple[str, int, int], ...]:
    return tuple(sorted((str(path), path.stat().st_mtime_ns, path.stat().st_size) for path in directory.glob("*.yaml")))


def ensure_rules_current() -> None:
    global _health
    if not _registry:
        reload_rules()
        return
    try:
        signature = _signature(_rules_path)
    except Exception as exc:
        _health = {**_health, "status": "reload_failed", "error": str(exc), "failed_at": time.time()}
        return
    if signature == _rules_signature:
        return
    try:
        reload_rules(_rules_path)
    except Exception as exc:
        _health = {**_health, "status": "reload_failed", "error": str(exc), "failed_at": time.time()}


def ruleset_health() -> dict:
    ensure_rules_current()
    return dict(_health)


def ruleset_hash() -> str:
    ensure_rules_current()
    return _ruleset_hash


def rules() -> tuple[Rule, ...]:
    ensure_rules_current()
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


def run_rules(ctx: BehaviorContext, window: str | None = None) -> list[Detection]:
    result = []
    for rule in rules():
        if window is not None and rule.window != window:
            continue
        if evaluate_condition(ctx, rule.condition):
            result.append(Detection(rule.id, rule.name, rule.severity, rule.mitre_technique,
                                    rule.points, f"{rule.description} (+{rule.points})",
                                    rule.version, rule.rule_type))
    return result
