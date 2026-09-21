from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.middleware.gzip import GZipMiddleware


def test_large_read_model_responses_are_compressed_without_changing_json_contract():
    app = FastAPI()
    app.add_middleware(GZipMiddleware, minimum_size=1024, compresslevel=5)

    @app.get("/read-model")
    def read_model():
        return {"items": [{"ip": "203.0.113.10", "evidence": "x" * 400} for _ in range(20)]}

    client = TestClient(app)
    response = client.get("/read-model", headers={"Accept-Encoding": "gzip"})

    assert response.status_code == 200
    assert response.headers["content-encoding"] == "gzip"
    assert response.json()["items"][0]["ip"] == "203.0.113.10"
