import json

from app.core import db
from app.core.logs import import_apache_lines
from app.collectors.websocket_collector import CollectorConfig, WebSocketCollector


def test_file_and_websocket_replay_produce_same_observation(tmp_path, monkeypatch):
    line = '198.51.100.30 - - [15/Aug/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404 12 "-" "fixture-client"'
    monkeypatch.setattr("app.ai.detector.load_model_bundle", lambda: None)

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "file.db")
    conn = db.connect()
    import_apache_lines(conn, [line], "fixture.log")
    file_obs = dict(conn.execute("SELECT * FROM ip_observations WHERE ip=?", ("198.51.100.30",)).fetchone())
    file_detections = json.loads(file_obs["detections_24h_json"])
    conn.close()

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "ws.db")
    collector = WebSocketCollector(CollectorConfig(False, "", "", "access", "fixture", 200, 500, 300))
    collector._commit_batch([line], len(line.encode()) + 1, 0)
    conn = db.connect()
    ws_obs = dict(conn.execute("SELECT * FROM ip_observations WHERE ip=?", ("198.51.100.30",)).fetchone())
    ws_detections = json.loads(ws_obs["detections_24h_json"])
    assert (file_obs["requests"], file_obs["status_4xx"], file_detections) == (ws_obs["requests"], ws_obs["status_4xx"], ws_detections)
    conn.close()
