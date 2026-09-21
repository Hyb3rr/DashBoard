import importlib

import pytest


@pytest.mark.parametrize("role", ["all", "api", "collector", "worker", "ai"])
def test_app_role_configuration_accepts_supported_roles(monkeypatch, role):
    monkeypatch.setenv("APP_ROLE", role)
    settings = importlib.import_module("app.config.settings")
    settings = importlib.reload(settings)
    assert settings.APP_ROLE == role


def test_app_role_configuration_rejects_unknown_role(monkeypatch):
    monkeypatch.setenv("APP_ROLE", "web-and-worker")
    settings = importlib.import_module("app.config.settings")
    with pytest.raises(ValueError, match="APP_ROLE"):
        importlib.reload(settings)
    monkeypatch.setenv("APP_ROLE", "all")
    importlib.reload(settings)


def test_scheduler_role_is_explicitly_standalone(monkeypatch):
    monkeypatch.setenv("APP_ROLE", "scheduler")
    settings = importlib.import_module("app.config.settings")
    with pytest.raises(ValueError, match="scripts.ops.data_scheduler"):
        importlib.reload(settings)
    monkeypatch.setenv("APP_ROLE", "all")
    importlib.reload(settings)
