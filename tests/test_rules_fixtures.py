import json
from pathlib import Path

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
