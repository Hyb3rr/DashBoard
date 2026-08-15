from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile
from typing import Any
from uuid import uuid4

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from ..config.settings import AI_MODEL_PATH, PROJECT_DIR
from ..core.db import decode, encode
from .features import FEATURE_COLUMNS, build_window_features

MODEL_KEY = "isolation_forest_v1"
MODEL_MODE = "persisted_v1"
MODEL_SCHEMA_VERSION = 1
MIN_WINDOWS = 50
DEFAULT_TRAIN_LOOKBACK_HOURS = 168
DEFAULT_SCORE_LOOKBACK_HOURS = 24
DEFAULT_MIN_IP_WINDOWS = 3
DEFAULT_EXPIRE_HOURS = 24


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _floor_minute(value: datetime) -> datetime:
    return value.astimezone(timezone.utc).replace(second=0, microsecond=0)


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(timezone.utc).isoformat() if value else None


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default


def model_path() -> Path:
    configured = os.getenv("AI_MODEL_PATH", str(AI_MODEL_PATH)).strip()
    path = Path(configured)
    return path if path.is_absolute() else PROJECT_DIR / path


def _fit_model_frame(frame: pd.DataFrame, metadata: dict[str, Any]) -> dict[str, Any]:
    scaler = StandardScaler()
    scaled = scaler.fit_transform(frame[FEATURE_COLUMNS])
    model = IsolationForest(
        n_estimators=300,
        contamination=0.02,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(scaled)
    decisions = model.decision_function(scaled)
    predictions = model.predict(scaled)
    anomalous = decisions[predictions == -1]
    floor = float(anomalous.min()) if len(anomalous) else float(decisions.min())
    return {
        "schema_version": MODEL_SCHEMA_VERSION,
        "model_version": metadata["model_version"],
        "trained_at": metadata["trained_at"],
        "feature_columns": list(FEATURE_COLUMNS),
        "training_start": metadata["training_start"],
        "training_end": metadata["training_end"],
        "training_windows": int(len(frame)),
        "training_ips": int(frame["ip"].nunique()),
        "training_decision_floor": floor,
        "scaler": scaler,
        "model": model,
    }


def _atomic_save(bundle: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            joblib.dump(bundle, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_model_bundle() -> dict[str, Any] | None:
    path = model_path()
    if not path.exists():
        return None
    try:
        bundle = joblib.load(path)
        if bundle.get("schema_version") != MODEL_SCHEMA_VERSION:
            return None
        if bundle.get("feature_columns") != FEATURE_COLUMNS:
            return None
        return bundle
    except Exception:
        return None


def _state(conn):
    row = conn.execute("SELECT * FROM ai_model_state WHERE model_key = ?", (MODEL_KEY,)).fetchone()
    if row:
        return row
    now = _iso(_utc_now())
    conn.execute(
        "INSERT INTO ai_model_state (model_key, updated_at) VALUES (?, ?)",
        (MODEL_KEY, now),
    )
    conn.commit()
    return conn.execute("SELECT * FROM ai_model_state WHERE model_key = ?", (MODEL_KEY,)).fetchone()


def train_model(conn, fit_executor=None) -> dict[str, Any]:
    """Fit and atomically persist a model; never destroys the old model."""
    now = _utc_now()
    _state(conn)
    end = _floor_minute(now)
    start = end - timedelta(hours=_env_int("LOG_WS_AI_TRAIN_LOOKBACK_HOURS", DEFAULT_TRAIN_LOOKBACK_HOURS))
    base = {"model_mode": MODEL_MODE, "status": "failed", "model_version": None}
    try:
        frame = build_window_features(conn, start, end)
        if len(frame) < MIN_WINDOWS:
            conn.execute(
                """UPDATE ai_model_state SET last_train_status=?, last_train_error=?, updated_at=?
                   WHERE model_key=?""",
                ("insufficient_data", f"{len(frame)} windows; need {MIN_WINDOWS}", _iso(now), MODEL_KEY),
            )
            conn.commit()
            return {**base, "status": "insufficient_data", "windows": len(frame), "ips": int(frame["ip"].nunique()) if not frame.empty else 0}

        metadata = {
            "model_version": uuid4().hex,
            "trained_at": _iso(now),
            "training_start": _iso(start),
            "training_end": _iso(end),
        }
        if fit_executor is None:
            bundle = _fit_model_frame(frame, metadata)
        else:
            bundle = fit_executor.submit(_fit_model_frame, frame, metadata).result()
        _atomic_save(bundle, model_path())
        conn.execute(
            """UPDATE ai_model_state SET model_version=?, trained_at=?, training_start=?, training_end=?,
               training_windows=?, training_ips=?, training_decision_floor=?, last_train_status=?,
               last_train_error=NULL, updated_at=? WHERE model_key=?""",
            (
                bundle["model_version"], bundle["trained_at"], bundle["training_start"], bundle["training_end"],
                bundle["training_windows"], bundle["training_ips"], bundle["training_decision_floor"],
                "trained", _iso(now), MODEL_KEY,
            ),
        )
        conn.commit()
        return {**base, "status": "trained", "model_version": bundle["model_version"], "trained_at": bundle["trained_at"], "windows": len(frame), "ips": int(frame["ip"].nunique())}
    except Exception as exc:
        conn.rollback()
        try:
            conn.execute(
                "UPDATE ai_model_state SET last_train_status=?, last_train_error=?, updated_at=? WHERE model_key=?",
                ("failed", f"{type(exc).__name__}: {exc}"[:240], _iso(now), MODEL_KEY),
            )
            conn.commit()
        except Exception:
            conn.rollback()
        return {**base, "error": type(exc).__name__}


def _confidence(windows: int) -> tuple[int, str]:
    value = min(100, windows * 10)
    level = "low" if windows < 3 else "medium" if windows < 10 else "high"
    return value, level


def _window_score(decision: float, floor: float) -> int:
    if floor == 0:
        return 100
    ratio = decision / floor
    return max(70, min(100, round(70 + 30 * ratio)))


def _feature_value(value):
    if pd.isna(value):
        return 0
    return float(value) if isinstance(value, (float,)) else int(value)


def _previous_evidence(value) -> dict[str, dict]:
    decoded = decode(value)
    return {str(item.get("window_start")): item for item in decoded if isinstance(item, dict) and item.get("window_start")}


def expire_inactive_scores(conn, now: datetime | None = None) -> int:
    now = now or _utc_now()
    cutoff = now - timedelta(hours=_env_int("LOG_WS_AI_EXPIRE_HOURS", DEFAULT_EXPIRE_HOURS))
    rows = conn.execute(
        "SELECT ip, ai_anomaly_score FROM ip_ai_scores WHERE last_window_at IS NOT NULL AND last_window_at < ? AND score_reason != 'inactivity_expired'",
        (_iso(cutoff),),
    ).fetchall()
    for row in rows:
        conn.execute(
            """UPDATE ip_ai_scores SET previous_ai_anomaly_score=?, score_delta=?, ai_anomaly_score=0,
               anomalous_windows=0, score_reason='inactivity_expired', scored_at=? WHERE ip=?""",
            (row["ai_anomaly_score"], -int(row["ai_anomaly_score"] or 0), _iso(now), row["ip"]),
        )
        conn.execute("INSERT INTO ip_change_log (ip, reason, changed_at) VALUES (?, 'ai', ?)", (row["ip"], _iso(now)))
    return len(rows)


def _trim_change_log(conn) -> None:
    conn.execute(
        "DELETE FROM ip_change_log WHERE seq <= "
        "(SELECT CASE WHEN MAX(seq) > 50000 THEN MAX(seq) - 50000 ELSE 0 END FROM ip_change_log)"
    )


def score_cycle(conn, force_full: bool = False) -> dict[str, Any]:
    """Score affected 24-hour windows with the persisted model."""
    now = _utc_now()
    end = _floor_minute(now)
    start = end - timedelta(hours=_env_int("LOG_WS_AI_SCORE_LOOKBACK_HOURS", DEFAULT_SCORE_LOOKBACK_HOURS))
    bundle = load_model_bundle()
    base = {"model_mode": MODEL_MODE, "model_version": bundle.get("model_version") if bundle else None}
    if bundle is None:
        return {**base, "status": "model_unavailable", "ips": 0, "windows": 0, "anomalous_windows": 0}

    state = _state(conn)
    cursor = int(state["last_scored_event_id"] or 0)
    max_event = conn.execute("SELECT COALESCE(MAX(id), 0) AS id FROM events").fetchone()["id"]
    recent_cutoff = _iso(now - timedelta(minutes=10))
    if force_full:
        ip_rows = conn.execute(
            "SELECT DISTINCT ip FROM ip_time_buckets WHERE bucket_minute >= ? AND bucket_minute < ?",
            (_iso(start), _iso(end)),
        ).fetchall()
    else:
        ip_rows = conn.execute(
            """SELECT DISTINCT ip FROM ip_time_buckets
               WHERE bucket_minute >= ? AND bucket_minute < ?""",
            (recent_cutoff, _iso(end)),
        ).fetchall()
    if not ip_rows:
        if force_full:
            ip_rows = conn.execute("SELECT DISTINCT src_ip AS ip FROM events WHERE timestamp >= ? AND timestamp < ?", (_iso(start), _iso(end))).fetchall()
        else:
            ip_rows = conn.execute(
                "SELECT DISTINCT src_ip AS ip FROM events WHERE id > ? OR (timestamp >= ? AND timestamp < ?)",
                (cursor, recent_cutoff, _iso(end)),
            ).fetchall()
    ips = [row["ip"] for row in ip_rows]
    expired = expire_inactive_scores(conn, now)
    if not ips:
        _trim_change_log(conn)
        conn.execute(
            "UPDATE ai_model_state SET last_scored_event_id=?, last_score_at=?, last_score_status=?, updated_at=? WHERE model_key=?",
            (max_event, _iso(now), "scored", _iso(now), MODEL_KEY),
        )
        conn.commit()
        return {**base, "status": "scored", "ips": 0, "windows": 0, "anomalous_windows": 0, "expired": expired, "changed_ips": expired, "cursor": max_event}

    frame = build_window_features(conn, start, end, ips)
    if frame.empty:
        _trim_change_log(conn)
        conn.execute("UPDATE ai_model_state SET last_scored_event_id=?, last_score_at=?, last_score_status=?, updated_at=? WHERE model_key=?", (max_event, _iso(now), "scored", _iso(now), MODEL_KEY))
        conn.commit()
        return {**base, "status": "scored", "ips": len(ips), "windows": 0, "anomalous_windows": 0, "expired": expired, "changed_ips": expired, "cursor": max_event}

    scaled = bundle["scaler"].transform(frame[FEATURE_COLUMNS])
    predictions = bundle["model"].predict(scaled)
    decisions = bundle["model"].decision_function(scaled)
    frame = frame.copy()
    frame["decision"] = decisions
    frame["is_anomaly"] = predictions == -1
    floor = float(bundle.get("training_decision_floor") or 0)
    frame["window_score"] = [_window_score(float(score), floor) if anomaly else 0 for score, anomaly in zip(decisions, predictions == -1)]
    scored_at = _iso(now)
    changed = 0
    anomaly_count = int(frame["is_anomaly"].sum())
    for ip, group in frame.groupby("ip", sort=True):
        previous = conn.execute("SELECT * FROM ip_ai_scores WHERE ip = ?", (ip,)).fetchone()
        previous_score = int(previous["ai_anomaly_score"] or 0) if previous else 0
        previous_map = _previous_evidence(previous["ai_evidence_json"] if previous else "[]")
        anomalies = group[group["is_anomaly"]].sort_values(["decision", "window_start"], ascending=[True, True])
        evidence = []
        for _, row in anomalies.head(3).iterrows():
            window_start = row["window_start"].isoformat()
            old = previous_map.get(window_start, {})
            window_score = int(row["window_score"])
            evidence.append({
                "window_start": window_start,
                "decision_score": float(row["decision"]),
                "window_score": window_score,
                "previous_window_score": old.get("window_score"),
                "window_score_delta": window_score - int(old["window_score"]) if old.get("window_score") is not None else None,
                "model_version": bundle["model_version"],
                "features": {column: _feature_value(row[column]) for column in FEATURE_COLUMNS},
            })
        confidence, confidence_level = _confidence(len(group))
        score = int(anomalies["window_score"].max()) if not anomalies.empty else 0
        reason = "model_refresh" if force_full else "new_traffic"
        if not anomalies.empty and len(group) < _env_int("LOG_WS_AI_MIN_IP_WINDOWS", DEFAULT_MIN_IP_WINDOWS):
            reason = "insufficient_ip_windows"
        elif anomalies.empty:
            reason = "normal"
        last_window = group["window_start"].max().isoformat()
        delta = score - previous_score
        old_tuple = tuple(previous[column] for column in ("ai_anomaly_score", "anomalous_windows", "windows_seen", "score_reason", "ai_evidence_json")) if previous else None
        new_tuple = (score, int(len(anomalies)), int(len(group)), reason, encode(evidence))
        conn.execute(
            """INSERT OR REPLACE INTO ip_ai_scores
              (ip,windows_seen,anomalous_windows,ai_anomaly_score,ai_evidence_json,model_mode,scored_at,
               confidence,confidence_level,previous_ai_anomaly_score,score_delta,score_reason,last_window_at,model_version)
              VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (ip, len(group), len(anomalies), score, encode(evidence), MODEL_MODE, scored_at,
             confidence, confidence_level, previous_score, delta, reason, last_window, bundle["model_version"]),
        )
        if old_tuple != new_tuple:
            conn.execute("INSERT INTO ip_change_log (ip, reason, changed_at) VALUES (?, 'ai', ?)", (ip, scored_at))
            changed += 1

    _trim_change_log(conn)
    conn.execute(
        """UPDATE ai_model_state SET last_scored_event_id=?, last_score_at=?, last_score_status=?, updated_at=?
           WHERE model_key=?""",
        (max_event, scored_at, "scored", scored_at, MODEL_KEY),
    )
    conn.commit()
    return {**base, "status": "scored", "ips": len(ips), "windows": len(frame), "anomalous_windows": anomaly_count, "changed_ips": changed + expired, "expired": expired, "cursor": max_event}


def score_import(conn) -> dict:
    """Backward-compatible entry point; never fits or clears persisted scores."""
    return score_cycle(conn, force_full=True)
