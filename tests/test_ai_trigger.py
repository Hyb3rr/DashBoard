from app.services.ai_trigger_consumer import AiTriggerConsumer
from app.services.ai_trigger_policy import TriggerEvent
from app.services.ai_trigger_policy import is_meaningful_trigger


class FakeRepository:
    def __init__(self, events):
        self.events = events
        self.recorded = []
        self.materialized = []

    def get_cursor(self):
        return 0

    def read_batch(self, after, limit):
        return self.events, self.events[-1].seq if self.events else 0

    def record_event(self, event, meaningful):
        self.recorded.append((event, meaningful))
        return "admitted" if meaningful else "ignored"

    def available_capacity(self, limit):
        return limit

    def deferred(self, limit):
        return []

    def materialize(self, item, identity, packet):
        self.materialized.append((item, identity, packet))
        return True


def test_disabled_consumer_does_not_read_or_create_jobs():
    repo = FakeRepository([TriggerEvent(1, "203.0.113.10", "classification", "unknown", "medium")])
    consumer = AiTriggerConsumer(repo, lambda _: {"subject": {"ip": "203.0.113.10"}}, enabled=False)
    assert consumer.run_once() == 0
    assert repo.recorded == []


def test_consumer_advances_traffic_and_creates_only_meaningful_job():
    events = [
        TriggerEvent(1, "203.0.113.10", "traffic"),
        TriggerEvent(2, "203.0.113.10", "classification", "unknown", "medium"),
    ]
    repo = FakeRepository(events)
    packet = {
        "subject": {"ip": "203.0.113.10"},
        "classification": {"label": "medium", "risk_score": 42, "confidence": 80},
        "evidence": [{"evidence_id": "ev_1", "source": "rule"}],
    }
    assert AiTriggerConsumer(repo, lambda _: packet, enabled=True).run_once() == 0
    assert repo.recorded == [(events[0], False), (events[1], True)]


def test_critical_transition_from_good_is_meaningful():
    assert is_meaningful_trigger(TriggerEvent(3, "203.0.113.11", "classification", "good", "critical"))
