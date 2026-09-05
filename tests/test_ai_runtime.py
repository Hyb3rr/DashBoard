import asyncio
import pytest

from app.services import ai_runtime as runtime_module


@pytest.mark.asyncio
async def test_slow_ai_cycle_isolated_from_runtime_lifecycle(monkeypatch):
    started = asyncio.Event()
    release = asyncio.Event()
    completed = asyncio.Event()

    async def slow_cycle():
        started.set()
        await release.wait()
        completed.set()
        return {"status": "completed"}

    monkeypatch.setenv("AI_RUNTIME_ENABLED", "true")
    monkeypatch.setenv("AI_RUNTIME_INTERVAL_SECONDS", "60")
    runtime = runtime_module.AiRuntime(slow_cycle, initial_delay_seconds=0)
    await runtime.start()
    await asyncio.wait_for(started.wait(), timeout=1)
    assert runtime.status()["running"] is True
    release.set()
    await asyncio.wait_for(completed.wait(), timeout=1)
    await runtime.stop()
    assert runtime.status()["running"] is False
    assert not any(task.get_name() == "ai-stage-2-runtime" for task in asyncio.all_tasks())


@pytest.mark.asyncio
async def test_disabled_ai_runtime_does_not_create_task(monkeypatch):
    monkeypatch.setenv("AI_RUNTIME_ENABLED", "false")
    runtime = runtime_module.AiRuntime(lambda: {"status": "completed"})
    await runtime.start()
    assert runtime.status()["running"] is False


@pytest.mark.asyncio
async def test_start_is_non_blocking_and_first_cycle_is_scheduled(monkeypatch):
    calls = []

    async def cycle():
        calls.append("ran")
        return {"status": "completed"}

    monkeypatch.setenv("AI_RUNTIME_ENABLED", "true")
    runtime = runtime_module.AiRuntime(cycle, initial_delay_seconds=60)
    await runtime.start()
    assert calls == []
    assert runtime.status()["running"] is True
    await runtime.stop()
    assert calls == []


def test_cycle_uses_detector_owned_connection_boundary(monkeypatch):
    calls = []

    class Cursor:
        def fetchone(self):
            return {"acquired": True}

    class Connection:
        def __enter__(self):
            calls.append("enter")
            return self

        def __exit__(self, *args):
            calls.append("exit")

        def execute(self, sql, params):
            calls.append(sql)
            return Cursor()

    monkeypatch.setattr(runtime_module.postgres, "connect", lambda: Connection())
    monkeypatch.setattr(runtime_module, "train_model", lambda conn: {"status": "trained"})
    monkeypatch.setattr(runtime_module, "score_cycle", lambda conn: {"status": "scored"})
    result = runtime_module.AiRuntime._run_cycle_sync()
    assert result["status"] == "completed"
    assert calls[0] == "enter"
    assert calls[-1] == "exit"
    assert any("pg_try_advisory_lock" in sql for sql in calls)
    assert any("pg_advisory_unlock" in sql for sql in calls)


def test_cycle_rolls_back_before_unlock_on_sql_failure(monkeypatch):
    calls = []

    class Cursor:
        def fetchone(self):
            return {"acquired": True}

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def execute(self, sql, params):
            calls.append(sql)
            return Cursor()

        def rollback(self):
            calls.append("rollback")

    monkeypatch.setattr(runtime_module.postgres, "connect", lambda: Connection())
    monkeypatch.setattr(runtime_module, "train_model", lambda conn: {"status": "trained"})

    def fail_score(conn):
        raise RuntimeError("score failed")

    monkeypatch.setattr(runtime_module, "score_cycle", fail_score)
    with pytest.raises(RuntimeError, match="score failed"):
        runtime_module.AiRuntime._run_cycle_sync()
    assert calls.index("rollback") < next(i for i, value in enumerate(calls) if "pg_advisory_unlock" in value)
