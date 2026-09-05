import json

from app.providers import pg_intel


class _Response:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.payload


def test_az0_partial_mirror_result_does_not_promote_snapshot(monkeypatch):
    manifest = {
        "provider": {
            "urls": ["https://bad.example/list", "https://good.example/list"],
            "ip_key": "ips",
        }
    }
    responses = iter((_Response(json.dumps(manifest).encode()), OSError("mirror unavailable"),
                      _Response(json.dumps({"ips": ["198.51.100.10"]}).encode())))
    promoted = []

    def fake_urlopen(_request, timeout):
        response = next(responses)
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(pg_intel, "urlopen", fake_urlopen)
    monkeypatch.setattr(pg_intel, "_privacy", lambda *args, **kwargs: promoted.append((args, kwargs)))

    result = pg_intel.refresh_az0(object(), url="https://manifest.example/manifest")

    assert result["status"] == "partial"
    assert result["providers"]["provider"]["status"] == "partial"
    assert result["providers"]["provider"]["records"] == 1
    assert result["records_upserted"] == 0
    assert promoted == []
