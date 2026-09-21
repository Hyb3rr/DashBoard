import asyncio

from starlette.requests import Request

from app.main import security_headers_middleware


def test_default_security_response_headers_are_present():
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/health",
        "raw_path": b"/health",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 1),
        "server": ("testserver", 80),
        "scheme": "http",
    }

    async def call_next(_request):
        from starlette.responses import Response

        return Response("ok")

    response = asyncio.run(security_headers_middleware(Request(scope), call_next))

    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["permissions-policy"] == "camera=(), microphone=(), geolocation=()"
