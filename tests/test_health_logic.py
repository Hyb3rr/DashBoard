from app.routers.health import _system_is_healthy


def _healthy_inputs():
    """Return a minimal fully healthy set of subsystem status payloads."""
    return (
        {"status": "ok"},
        {"postgres": {"status": "ok"}, "clickhouse": {"status": "ok"}},
        {"enabled": False},
        {"status": "running"},
        {"status": "running"},
        "api",
    )


def test_system_health_accepts_healthy_subsystems():
    """Treat healthy storage, rules, collector, watcher, and realtime as ready."""
    assert _system_is_healthy(*_healthy_inputs()) is True


def test_api_health_degrades_when_realtime_listener_is_unavailable():
    """Require a running or disabled realtime listener for API roles."""
    inputs = list(_healthy_inputs())
    inputs[4] = {"status": "retrying"}
    assert _system_is_healthy(*inputs) is False


def test_worker_health_does_not_require_api_realtime_listener():
    """Ignore API-only realtime listener readiness in background worker roles."""
    inputs = list(_healthy_inputs())
    inputs[4] = {"status": "not_started"}
    inputs[5] = "worker"
    assert _system_is_healthy(*inputs) is True


def test_collector_health_degrades_on_failed_archive_writer():
    """Mark the system degraded when an enabled collector archive has failed."""
    inputs = list(_healthy_inputs())
    inputs[2] = {"enabled": True, "raw_archive": {"writer_status": "FAILED"}}
    assert _system_is_healthy(*inputs) is False
