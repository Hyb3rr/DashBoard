import re

from app.core.request_context import request_id
from starlette.middleware.trustedhost import TrustedHostMiddleware
from fastapi import FastAPI
from fastapi.testclient import TestClient


def test_valid_request_id_is_preserved():
    assert request_id("analyst-42:dashboard") == "analyst-42:dashboard"


def test_invalid_request_id_is_replaced_with_safe_identifier():
    generated = request_id("bad value\nforged")
    assert re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", generated)
    assert request_id("x" * 129) != "x" * 129


def test_trusted_host_boundary_rejects_unconfigured_host():
    app = FastAPI()
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["sentinel.test"])

    @app.get("/")
    def root():
        return {"ok": True}

    client = TestClient(app)
    assert client.get("/", headers={"host": "sentinel.test"}).status_code == 200
    assert client.get("/", headers={"host": "attacker.test"}).status_code == 400
