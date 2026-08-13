from __future__ import annotations

from datetime import datetime, timezone
import sqlite3

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from ..core.db import encode
from .features import FEATURE_COLUMNS, build_window_features

MODEL_MODE = "fit_per_import"
MIN_WINDOWS = 50


def _clear_scores(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM ip_ai_scores")


def _get_model(df: pd.DataFrame):
    scaler = StandardScaler()
    scaled = scaler.fit_transform(df[FEATURE_COLUMNS])
    model = IsolationForest(
        n_estimators=300,
        contamination=0.02,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(scaled)
    return model, scaler


def _score_window(decision: float, minimum: float) -> int:
    ratio = 1.0 if minimum == 0 else decision / minimum
    return max(70, min(100, round(70 + 30 * ratio)))


def score_import(conn: sqlite3.Connection) -> dict:
    base = {"model_mode": MODEL_MODE}
    try:
        frame = build_window_features(conn)
        windows = len(frame)
        if windows < MIN_WINDOWS:
            _clear_scores(conn)
            return {**base, "status": "insufficient_data", "windows": windows, "ips": 0, "anomalous_windows": 0}

        model, scaler = _get_model(frame)
        scaled = scaler.transform(frame[FEATURE_COLUMNS])
        predictions = model.predict(scaled)
        decisions = model.decision_function(scaled)
        anomalous = predictions == -1
        minimum = float(decisions[anomalous].min()) if anomalous.any() else 0.0
        frame = frame.copy()
        frame["decision"] = decisions
        frame["window_score"] = [
            _score_window(float(score), minimum) if is_anomaly else 0
            for score, is_anomaly in zip(decisions, anomalous)
        ]
        frame["is_anomaly"] = anomalous

        _clear_scores(conn)
        scored_at = datetime.now(timezone.utc).isoformat()
        for ip, group in frame.groupby("ip", sort=True):
            anomalies = group[group["is_anomaly"]].sort_values(
                ["decision", "window_start"], ascending=[True, True]
            )
            evidence = []
            for _, row in anomalies.head(3).iterrows():
                evidence.append({
                    "window_start": row["window_start"].isoformat(),
                    "decision_score": float(row["decision"]),
                    "window_score": int(row["window_score"]),
                    "features": {
                        column: float(row[column]) if isinstance(row[column], float) else int(row[column])
                        for column in FEATURE_COLUMNS
                    },
                })
            conn.execute(
                """
                INSERT OR REPLACE INTO ip_ai_scores
                  (ip, windows_seen, anomalous_windows, ai_anomaly_score,
                   ai_evidence_json, model_mode, scored_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ip,
                    int(len(group)),
                    int(len(anomalies)),
                    int(anomalies["window_score"].max()) if not anomalies.empty else 0,
                    encode(evidence),
                    MODEL_MODE,
                    scored_at,
                ),
            )
        return {
            **base,
            "status": "scored",
            "windows": windows,
            "ips": int(frame["ip"].nunique()),
            "anomalous_windows": int(anomalous.sum()),
        }
    except Exception:
        try:
            _clear_scores(conn)
        except Exception:
            pass
        return {**base, "status": "failed", "windows": 0, "ips": 0, "anomalous_windows": 0}
