from app.services.workload_governor import WorkloadGovernor


def test_normal_mode_preserves_background_work():
    governor = WorkloadGovernor()

    state = governor.update(storage_queue_depth=10, storage_oldest_age_ms=100)

    assert state.mode == "NORMAL"
    assert governor.allow_rare_path()
    assert governor.allow_enrichment()


def test_pressure_keeps_ingest_but_defers_rare_path():
    governor = WorkloadGovernor(pressure_depth=5, critical_depth=10)

    state = governor.update(storage_queue_depth=5)

    assert state.mode == "PRESSURE"
    assert not governor.allow_rare_path()
    assert governor.allow_enrichment()


def test_critical_preserves_ingest_and_alerts_but_defers_background_work():
    governor = WorkloadGovernor(pressure_depth=5, critical_depth=10)

    state = governor.update(storage_queue_depth=10)

    assert state.mode == "CRITICAL"
    assert not governor.allow_rare_path()
    assert not governor.allow_enrichment()


def test_oldest_event_age_can_trigger_pressure():
    governor = WorkloadGovernor(pressure_age_ms=100, critical_age_ms=200)

    assert governor.update(0, 100).mode == "PRESSURE"
    assert governor.update(0, 200).mode == "CRITICAL"
