from datetime import datetime, timedelta, timezone

from app.core import db


def _event_rows(now, count=60, ip="8.8.8.8"):
    return [
        (
            "ws:test", f"{ip}-{index}", "raw", (now - timedelta(minutes=index + 1)).isoformat(),
            ip, "GET", "/missing", 404, 10, "ua", now.isoformat(),
        )
        for index in range(count)
    ]


def test_window_features_are_bounded_and_filter_ips(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "hub.db")
    monkeypatch.setattr(db, "REGION_SEED_PATH", tmp_path / "missing.seed.json")
    conn = db.connect()
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    conn.executemany(
        """INSERT INTO events
           (source,line_hash,raw_line,timestamp,src_ip,method,path,status,bytes_sent,user_agent,imported_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        _event_rows(now, 3, "8.8.8.8") + _event_rows(now, 2, "1.1.1.1"),
    )
    from app.ai.features import build_window_features

    frame = build_window_features(conn, now - timedelta(minutes=2), now, ["8.8.8.8"])
    assert set(frame["ip"]) == {"8.8.8.8"}
    assert len(frame) == 2
    conn.close()


def test_train_persists_artifact_and_score_does_not_fit_again(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "hub.db")
    monkeypatch.setattr(db, "REGION_SEED_PATH", tmp_path / "missing.seed.json")
    monkeypatch.setenv("AI_MODEL_PATH", str(tmp_path / "model.joblib"))
    conn = db.connect()
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    conn.executemany(
        """INSERT INTO events
           (source,line_hash,raw_line,timestamp,src_ip,method,path,status,bytes_sent,user_agent,imported_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        _event_rows(now, 60),
    )
    from app.ai.detector import score_cycle, train_model

    trained = train_model(conn)
    assert trained["status"] == "trained"
    assert (tmp_path / "model.joblib").exists()

    from sklearn.ensemble import IsolationForest
    original_fit = IsolationForest.fit

    def fail_fit(*args, **kwargs):
        raise AssertionError("score cycle must not fit")

    monkeypatch.setattr(IsolationForest, "fit", fail_fit)
    scored = score_cycle(conn, force_full=True)
    assert scored["status"] == "scored"
    monkeypatch.setattr(IsolationForest, "fit", original_fit)
    conn.close()


def test_inactive_ai_score_expires_without_deleting_row(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "hub.db")
    monkeypatch.setattr(db, "REGION_SEED_PATH", tmp_path / "missing.seed.json")
    conn = db.connect()
    old = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
    conn.execute(
        """INSERT INTO ip_ai_scores
           (ip,windows_seen,anomalous_windows,ai_anomaly_score,ai_evidence_json,model_mode,scored_at,last_window_at)
           VALUES (?,?,?,?,?,?,?,?)""",
        ("8.8.8.8", 10, 2, 90, "[]", "persisted_v1", old, old),
    )
    from app.ai.detector import expire_inactive_scores

    assert expire_inactive_scores(conn) == 1
    row = conn.execute("SELECT * FROM ip_ai_scores WHERE ip='8.8.8.8'").fetchone()
    assert row["ai_anomaly_score"] == 0
    assert row["score_reason"] == "inactivity_expired"
    assert row["previous_ai_anomaly_score"] == 90
    conn.close()
