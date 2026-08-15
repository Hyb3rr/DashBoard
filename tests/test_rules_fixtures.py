import json
from pathlib import Path
import pytest

from app.core.rules import BehaviorContext, load_rules, run_rules


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


@pytest.mark.parametrize("field,value,extra", [
    ("requests", "x", {}),
    ("requests", 1, {"operator": "contains"}),
])
def test_loader_rejects_invalid_condition_types(tmp_path, field, value, extra):
    operator = extra.get("operator", "gt")
    (tmp_path / "invalid.yaml").write_text(f"""
id: TEST-INVALID
name: invalid
severity: low
points: 1
rule_type: anomaly
mitre_technique:
window: 1h
description: invalid
false_positive_notes: [test]
version: 1
enabled: true
condition:
  field: {field}
  operator: {operator}
  value: {json.dumps(value)}
""", encoding="utf-8")
    with pytest.raises(ValueError):
        load_rules(tmp_path)


def test_loader_rejects_invalid_rule_type_and_anomaly_mitre(tmp_path):
    for value in ("typo", "anomaly"):
        mitre = "T1595.003" if value == "anomaly" else ""
        (tmp_path / "invalid.yaml").write_text(f"""
id: TEST-INVALID
name: invalid
severity: low
points: 1
rule_type: {value}
mitre_technique: {mitre}
window: 1h
description: invalid
false_positive_notes: [test]
version: 1
enabled: true
condition: {{field: requests, operator: gt, value: 1}}
""", encoding="utf-8")
        with pytest.raises(ValueError):
            load_rules(tmp_path)
