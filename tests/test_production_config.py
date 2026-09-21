from scripts.ops.validate_production_config import validate_environment


def _env(**overrides):
    values = {
        "APP_ROLE": "api",
        "POSTGRES_DSN": "postgresql://redacted",
        "CLICKHOUSE_HOST": "127.0.0.1",
        "AUTH_REQUIRED": "true",
        "AUTH_TRUSTED_PROXY_CIDRS": "127.0.0.1/32",
        "SECURITY_HEADERS_ENABLED": "true",
        "TRUSTED_HOSTS": "sentinel.example.com",
    }
    values.update(overrides)
    return values


def test_exposed_api_configuration_passes():
    assert validate_environment(_env()) == []


def test_exposed_configuration_fails_closed_for_missing_boundary_settings():
    errors = validate_environment(_env(AUTH_REQUIRED="false", AUTH_TRUSTED_PROXY_CIDRS="", TRUSTED_HOSTS="*"))
    assert "AUTH_REQUIRED must be true for an exposed deployment" in errors
    assert "AUTH_TRUSTED_PROXY_CIDRS is required when AUTH_REQUIRED is true" not in errors
    assert "TRUSTED_HOSTS must not contain wildcard '*'" in errors


def test_collector_configuration_requires_remote_log_credentials():
    errors = validate_environment(_env(APP_ROLE="collector", LOG_WS_ENABLED="true"))
    assert "LOG_WS_URL is required when LOG_WS_ENABLED is true" in errors
    assert "LOG_WS_TOKEN is required when LOG_WS_ENABLED is true" in errors
    assert "LOG_WS_SOURCE_ID is required when LOG_WS_ENABLED is true" in errors
