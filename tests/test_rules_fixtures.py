import json
from pathlib import Path
import pytest

from app.core.rules import BehaviorContext, load_rules, load_rules_json, run_rules


def test_every_enabled_rule_has_fire_and_not_fire_fixture():
    rules, _ = load_rules()
    fixture_dir = Path(__file__).parent / "fixtures" / "rules"
    for rule in rules:
        fire = fixture_dir / f"{rule.id}.fire.json"
        not_fire = fixture_dir / f"{rule.id}.not-fire.json"
        assert fire.exists()
        assert not_fire.exists()
        for path, expected in ((fire, True), (not_fire, False)):
            fixture = json.loads(path.read_text(encoding="utf-8"))
            assert fixture["rule_id"] == rule.id
            context = BehaviorContext(**fixture["context"])
            fired = any(item.id == rule.id for item in run_rules(context, rule.window))
            assert fired is expected, path.name


def test_rule_window_is_enforced():
    rules, _ = load_rules()
    burst = next(rule for rule in rules if rule.id == "WEB-BURST-001")
    context = BehaviorContext(peak_requests_1m=100)
    assert not any(item.id == burst.id for item in run_rules(context, "24h"))
    assert any(item.id == burst.id for item in run_rules(context, "1h"))


def test_json_loader_is_available_for_format_parity(tmp_path):
    payload = {
        "id": "TEST-JSON-001", "name": "json", "severity": "low", "points": 1,
        "rule_type": "anomaly", "mitre_technique": None, "window": "1h",
        "description": "json", "false_positive_notes": ["test"], "version": 1,
        "enabled": True, "condition": {"field": "requests", "operator": "gt", "value": 1},
    }
    (tmp_path / "rule.json").write_text(json.dumps(payload), encoding="utf-8")
    rules, _ = load_rules_json(tmp_path)
    assert rules[0].id == "TEST-JSON-001"


@pytest.mark.parametrize("field,value,extra", [
    ("requests", "x", {}),
    ("requests", 1, {"operator": "contains"}),
])
def test_loader_rejects_invalid_condition_types(tmp_path, field, value, extra):
    operator = extra.get("operator", "gt")
    (tmp_path / "invalid.json").write_text(json.dumps({
        "id": "TEST-INVALID", "name": "invalid", "severity": "low", "points": 1,
        "rule_type": "anomaly", "mitre_technique": None, "window": "1h",
        "description": "invalid", "false_positive_notes": ["test"], "version": 1,
        "enabled": True, "condition": {"field": field, "operator": operator, "value": value},
    }), encoding="utf-8")
    with pytest.raises(ValueError):
        load_rules(tmp_path)


def test_loader_rejects_invalid_rule_type_and_anomaly_mitre(tmp_path):
    for value in ("typo", "anomaly"):
        mitre = "T1595.003" if value == "anomaly" else ""
        (tmp_path / "invalid.json").write_text(json.dumps({
            "id": "TEST-INVALID", "name": "invalid", "severity": "low", "points": 1,
            "rule_type": value, "mitre_technique": mitre or None, "window": "1h",
            "description": "invalid", "false_positive_notes": ["test"], "version": 1,
            "enabled": True, "condition": {"field": "requests", "operator": "gt", "value": 1},
        }), encoding="utf-8")
        with pytest.raises(ValueError):
            load_rules(tmp_path)
