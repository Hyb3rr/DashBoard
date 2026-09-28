from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import tempfile
from typing import Any
from uuid import uuid4

import joblib
import pandas as pd
from psycopg.types.json import Jsonb
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from ..config.settings import AI_MODEL_PATH, PROJECT_DIR
from ..core.json_utils import decode
from ..core.change_feed import append_ip_changes
from ..core.evidence import UnifiedEvidence
from .features import FEATURE_COLUMNS, build_window_features

MODEL_KEY = "isolation_forest_v1"
MODEL_MODE = "persisted_v1"
MODEL_SCHEMA_VERSION = 1
MIN_WINDOWS = 50
DEFAULT_TRAIN_LOOKBACK_HOURS = 168
DEFAULT_SCORE_LOOKBACK_HOURS = 24
DEFAULT_MIN_IP_WINDOWS = 3
DEFAULT_EXPIRE_HOURS = 24
DEFAULT_TRAIN_MAX_WINDOWS = 100_000
DEFAULT_TRAIN_MAX_IPS = 10_000
DEFAULT_TRAIN_N_JOBS = 2


def _utc_now() -> datetime:
    """Return the current UTC time for model and scoring lifecycle records."""
    return datetime.now(timezone.utc)


def _floor_minute(value: datetime) -> datetime:
    """Align a timestamp to the start of its UTC minute."""
    return value.astimezone(timezone.utc).replace(second=0, microsecond=0)


def _iso(value: datetime | None) -> str | None:
    """Serialize an optional timestamp in UTC."""
    return value.astimezone(timezone.utc).isoformat() if value else None


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    """Read a bounded positive integer setting with a safe default."""
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default


def model_path() -> Path:
    """Resolve the configured Isolation Forest artifact path."""
    configured = os.getenv("AI_MODEL_PATH", str(AI_MODEL_PATH)).strip()
    path = Path(configured)
    return path if path.is_absolute() else PROJECT_DIR / path


def _fit_model_frame(frame: pd.DataFrame, metadata: dict[str, Any]) -> dict[str, Any]:
    """Fit the scaler and Isolation Forest and return a versioned model bundle."""
    scaler = StandardScaler()
    scaled = scaler.fit_transform(frame[FEATURE_COLUMNS])
    model = IsolationForest(
        n_estimators=300,
        contamination=0.02,
        random_state=42,
        n_jobs=_env_int("AI_TRAIN_N_JOBS", DEFAULT_TRAIN_N_JOBS),
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
        "training_windows_before_bound": int(metadata.get("training_windows_before_bound", len(frame))),
        "training_ips_before_bound": int(metadata.get("training_ips_before_bound", frame["ip"].nunique())),
        "training_input_bounded": bool(metadata.get("training_input_bounded", False)),
        "training_source_rows_bounded": bool(metadata.get("training_source_rows_bounded", False)),
        "training_source_row_limit": metadata.get("training_source_row_limit"),
        "training_source_ip_limit": metadata.get("training_source_ip_limit"),
        "training_decision_floor": floor,
        "scaler": scaler,
        "model": model,
    }


def _atomic_save(bundle: dict[str, Any], path: Path) -> None:
    """Persist a model bundle atomically and sync its file and directory."""
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
    """Load a compatible model artifact or return unavailable."""
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
    """Read or initialize the persisted Isolation Forest lifecycle row."""
    row = conn.execute("SELECT * FROM ai_model_state WHERE model_key = %s", (MODEL_KEY,)).fetchone()
    if row:
        return row
    now = _iso(_utc_now())
    conn.execute(
        "INSERT INTO ai_model_state (model_key, updated_at) VALUES (%s, %s)",
        (MODEL_KEY, now),
    )
    conn.commit()
    return conn.execute("SELECT * FROM ai_model_state WHERE model_key = %s", (MODEL_KEY,)).fetchone()


def _feature_frame(conn, start: datetime, end: datetime, ips: list[str] | None = None) -> pd.DataFrame:
    """Read bounded minute features and derive model windows."""
    max_ips = _env_int("AI_TRAIN_MAX_IPS", DEFAULT_TRAIN_MAX_IPS)
    max_windows = _env_int("AI_TRAIN_MAX_WINDOWS", DEFAULT_TRAIN_MAX_WINDOWS)
    sql = """SELECT host(f.ip) AS ip, f.bucket_minute, f.requests,
                     COALESCE(p.unique_paths_approx, 0) AS unique_paths_approx,
                     f.status_404, f.status_403, f.status_5xx, f.post_requests,
                     f.sensitive_hits, f.wp_login_hits, f.bytes_sum
              FROM ip_minute_features f
              LEFT JOIN (
                SELECT dataset_id, ip, bucket_minute, COUNT(*) AS unique_paths_approx
                FROM ip_minute_path_seen
                GROUP BY dataset_id, ip, bucket_minute
              ) p ON p.dataset_id=f.dataset_id AND p.ip=f.ip AND p.bucket_minute=f.bucket_minute
              WHERE f.dataset_id=%s AND f.bucket_minute >= %s AND f.bucket_minute < %s"""
    params: list[Any] = ["live", start, end]
    if ips is not None:
        params.extend([ips])
    else:
        sql = """WITH selected_ips AS (
                    SELECT f.ip
                      FROM ip_minute_features f
                     WHERE f.dataset_id=%s AND f.bucket_minute >= %s AND f.bucket_minute < %s
                     GROUP BY f.ip
                     ORDER BY md5(host(f.ip)), host(f.ip)
                     LIMIT %s
                ), bounded_features AS (
                    SELECT f.*,
                           row_number() OVER (ORDER BY f.bucket_minute DESC, host(f.ip), f.dataset_id) AS source_rank
                      FROM ip_minute_features f
                      JOIN selected_ips s ON s.ip=f.ip
                     WHERE f.dataset_id=%s AND f.bucket_minute >= %s AND f.bucket_minute < %s
                ), bounded_paths AS (
                    SELECT p.dataset_id, p.ip, p.bucket_minute, COUNT(*) AS unique_paths_approx
                      FROM ip_minute_path_seen p
                      JOIN selected_ips s ON s.ip=p.ip
                     WHERE p.dataset_id=%s AND p.bucket_minute >= %s AND p.bucket_minute < %s
                     GROUP BY p.dataset_id, p.ip, p.bucket_minute
                )
                SELECT host(f.ip) AS ip, f.bucket_minute, f.requests,
                       COALESCE(p.unique_paths_approx, 0) AS unique_paths_approx,
                       f.status_404, f.status_403, f.status_5xx, f.post_requests,
                       f.sensitive_hits, f.wp_login_hits, f.bytes_sum
                  FROM bounded_features f
                  LEFT JOIN bounded_paths p
                    ON p.dataset_id=f.dataset_id AND p.ip=f.ip AND p.bucket_minute=f.bucket_minute
                 WHERE f.source_rank <= %s"""
        params = ["live", start, end, max_ips, "live", start, end, "live", start, end, max_windows]
    if ips is not None:
        sql += " AND f.ip=ANY(%s::inet[])"
    rows = conn.execute(sql, params).fetchall()
    frame = build_window_features([dict(row) for row in rows])
    if ips is None:
        frame.attrs["training_source_rows_bounded"] = True
        frame.attrs["training_source_row_limit"] = max_windows
        frame.attrs["training_source_ip_limit"] = max_ips
    return frame


def _bound_training_frame(frame: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Apply deterministic AI resource limits without row-order truncation."""
    before_windows = len(frame)
    before_ips = int(frame["ip"].nunique()) if not frame.empty else 0
    max_ips = _env_int("AI_TRAIN_MAX_IPS", DEFAULT_TRAIN_MAX_IPS)
    max_windows = _env_int("AI_TRAIN_MAX_WINDOWS", DEFAULT_TRAIN_MAX_WINDOWS)
    bounded = frame
    if before_ips > max_ips:
        ranked = sorted(
            (str(ip) for ip in frame["ip"].dropna().unique()),
            key=lambda ip: (hashlib.sha256(ip.encode("utf-8")).hexdigest(), ip),
        )
        keep = set(ranked[:max_ips])
        bounded = bounded[bounded["ip"].astype(str).isin(keep)]
    if len(bounded) > max_windows:
        bounded = bounded.sort_values(["window_start", "ip"], ascending=[False, True], kind="mergesort").head(max_windows)
    bounded = bounded.sort_values(["ip", "window_start"], kind="mergesort").reset_index(drop=True)
    metadata = {
        "training_windows_before_bound": before_windows,
        "training_ips_before_bound": before_ips,
        "training_input_bounded": len(bounded) != before_windows or int(bounded["ip"].nunique()) != before_ips,
    }
    return bounded, metadata


def train_model(conn, fit_executor=None) -> dict[str, Any]:
    """Fit and atomically persist a model; never destroys the old model."""
    now = _utc_now()
    _state(conn)
    end = _floor_minute(now)
    start = end - timedelta(hours=_env_int("LOG_WS_AI_TRAIN_LOOKBACK_HOURS", DEFAULT_TRAIN_LOOKBACK_HOURS))
    base = {"model_mode": MODEL_MODE, "status": "failed", "model_version": None}
    try:
        frame = _feature_frame(conn, start, end)
        frame, bound_metadata = _bound_training_frame(frame)
        if len(frame) < MIN_WINDOWS:
            conn.execute(
                """UPDATE ai_model_state SET last_train_status=%s, last_train_error=%s, updated_at=%s
                   WHERE model_key=%s""",
                ("insufficient_data", f"{len(frame)} windows; need {MIN_WINDOWS}", _iso(now), MODEL_KEY),
            )
            conn.commit()
            return {**base, "status": "insufficient_data", "windows": len(frame), "ips": int(frame["ip"].nunique()) if not frame.empty else 0}

        metadata = {
            "model_version": uuid4().hex,
            "trained_at": _iso(now),
            "training_start": _iso(start),
            "training_end": _iso(end),
            **bound_metadata,
            "training_source_rows_bounded": bool(frame.attrs.get("training_source_rows_bounded", False)),
            "training_source_row_limit": frame.attrs.get("training_source_row_limit"),
            "training_source_ip_limit": frame.attrs.get("training_source_ip_limit"),
        }
        if fit_executor is None:
            bundle = _fit_model_frame(frame, metadata)
        else:
            bundle = fit_executor.submit(_fit_model_frame, frame, metadata).result()
        _atomic_save(bundle, model_path())
        conn.execute(
            """UPDATE ai_model_state SET model_version=%s, trained_at=%s, training_start=%s, training_end=%s,
               training_windows=%s, training_ips=%s, training_decision_floor=%s, last_train_status=%s,
               last_train_error=NULL, updated_at=%s WHERE model_key=%s""",
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
                "UPDATE ai_model_state SET last_train_status=%s, last_train_error=%s, updated_at=%s WHERE model_key=%s",
                ("failed", f"{type(exc).__name__}: {exc}"[:240], _iso(now), MODEL_KEY),
            )
            conn.commit()
        except Exception:
            conn.rollback()
        return {**base, "error": type(exc).__name__}


def _confidence(windows: int) -> tuple[int, str]:
    """Map observed model-window count to the existing confidence contract."""
    value = min(100, windows * 10)
    level = "low" if windows < 3 else "medium" if windows < 10 else "high"
    return value, level


def _window_score(decision: float, floor: float) -> int:
    """Convert a model decision score into the bounded anomaly window score."""
    if floor == 0:
        return 100
    ratio = decision / floor
    return max(70, min(100, round(70 + 30 * ratio)))


def _feature_value(value):
    """Convert a model feature to a JSON-safe numeric value."""
    if pd.isna(value):
        return 0
    return float(value) if isinstance(value, (float,)) else int(value)


def _previous_evidence(value) -> dict[str, dict]:
    """Index prior AI evidence by its observed window start."""
    decoded = decode(value)
    return {str(item.get("window_start")): item for item in decoded if isinstance(item, dict) and item.get("window_start")}


def expire_inactive_scores(conn, now: datetime | None = None) -> int:
    """Clear stale anomaly scores while preserving their previous state."""
    now = now or _utc_now()
    cutoff = now - timedelta(hours=_env_int("LOG_WS_AI_EXPIRE_HOURS", DEFAULT_EXPIRE_HOURS))
    rows = conn.execute(
        "SELECT ip, ai_anomaly_score FROM ip_ai_scores WHERE last_window_at IS NOT NULL AND last_window_at < %s AND score_reason != 'inactivity_expired'",
        (_iso(cutoff),),
    ).fetchall()
    for row in rows:
        conn.execute(
            """UPDATE ip_ai_scores SET previous_ai_anomaly_score=%s, score_delta=%s, ai_anomaly_score=0,
               anomalous_windows=0, score_reason='inactivity_expired', scored_at=%s WHERE ip=%s""",
            (row["ai_anomaly_score"], -int(row["ai_anomaly_score"] or 0), _iso(now), row["ip"]),
        )
        append_ip_changes(conn, (row["ip"],), "ai", _iso(now))
    return len(rows)


def _score_windows(frame: pd.DataFrame, bundle: dict[str, Any]) -> tuple[pd.DataFrame, int]:
    """Apply the persisted model to feature windows and mark anomalous rows."""
    scaled = bundle["scaler"].transform(frame[FEATURE_COLUMNS])
    predictions = bundle["model"].predict(scaled)
    decisions = bundle["model"].decision_function(scaled)
    scored = frame.copy()
    scored["decision"] = decisions
    scored["is_anomaly"] = predictions == -1
    floor = float(bundle.get("training_decision_floor") or 0)
    scored["window_score"] = [
        _window_score(float(score), floor) if anomaly else 0
        for score, anomaly in zip(decisions, predictions == -1)
    ]
    return scored, int(scored["is_anomaly"].sum())


def _anomaly_evidence(row: pd.Series, previous: dict[str, Any], bundle: dict[str, Any], floor: float) -> dict[str, Any]:
    """Build one explainable evidence record for an anomalous model window."""
    window_start = row["window_start"].isoformat()
    window_score = int(row["window_score"])
    features = {column: _feature_value(row[column]) for column in FEATURE_COLUMNS}
    contract = UnifiedEvidence(
        source="isolation_forest",
        type="isolation_forest",
        severity="supporting",
        observed={"window_start": window_start, "features": features},
        baseline={"model_version": bundle["model_version"], "decision_floor": floor},
        score_contribution=0,
        observed_at=window_start,
        description="Isolation Forest flagged an anomalous traffic window.",
        supporting_context={"decision_score": float(row["decision"]), "window_score": window_score},
        mode=MODEL_MODE,
    ).to_dict()
    contract.update({
        "window_start": window_start,
        "decision_score": float(row["decision"]),
        "window_score": window_score,
        "previous_window_score": previous.get("window_score"),
        "window_score_delta": window_score - int(previous["window_score"])
        if previous.get("window_score") is not None else None,
        "model_version": bundle["model_version"],
        "features": features,
    })
    return contract


def _build_ip_score(ip: str, group: pd.DataFrame, previous: dict[str, Any] | None,
                    bundle: dict[str, Any], scored_at: str, force_full: bool) -> dict[str, Any]:
    """Assemble current anomaly score, confidence, reason, and evidence for one IP."""
    previous_score = int(previous["ai_anomaly_score"] or 0) if previous else 0
    previous_map = _previous_evidence(previous["ai_evidence_json"] if previous else "[]")
    anomalies = group[group["is_anomaly"]].sort_values(["decision", "window_start"], ascending=[True, True])
    floor = float(bundle.get("training_decision_floor") or 0)
    evidence = [
        _anomaly_evidence(row, previous_map.get(row["window_start"].isoformat(), {}), bundle, floor)
        for _, row in anomalies.head(3).iterrows()
    ]
    confidence, confidence_level = _confidence(len(group))
    score = int(anomalies["window_score"].max()) if not anomalies.empty else 0
    reason = "model_refresh" if force_full else "new_traffic"
    if not anomalies.empty and len(group) < _env_int("LOG_WS_AI_MIN_IP_WINDOWS", DEFAULT_MIN_IP_WINDOWS):
        reason = "insufficient_ip_windows"
    elif anomalies.empty:
        reason = "normal"
    return {
        "ip": ip,
        "windows_seen": len(group),
        "anomalous_windows": len(anomalies),
        "score": score,
        "evidence": evidence,
        "confidence": confidence,
        "confidence_level": confidence_level,
        "previous_score": previous_score,
        "score_delta": score - previous_score,
        "reason": reason,
        "last_window_at": group["window_start"].max().isoformat(),
        "scored_at": scored_at,
        "model_version": bundle["model_version"],
    }


def _persist_ip_score(conn, score: dict[str, Any], previous: dict[str, Any] | None) -> bool:
    """Upsert one IP's anomaly read model and emit a change only when it differs."""
    old_tuple = tuple(previous[column] for column in (
        "ai_anomaly_score", "anomalous_windows", "windows_seen", "score_reason", "ai_evidence_json"
    )) if previous else None
    new_tuple = (
        score["score"], score["anomalous_windows"], score["windows_seen"],
        score["reason"], Jsonb(score["evidence"]),
    )
    conn.execute(
        """INSERT INTO ip_ai_scores
          (ip,windows_seen,anomalous_windows,ai_anomaly_score,ai_evidence_json,model_mode,scored_at,
           confidence,confidence_level,previous_ai_anomaly_score,score_delta,score_reason,last_window_at,model_version)
          VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
          ON CONFLICT (ip) DO UPDATE SET
            windows_seen=EXCLUDED.windows_seen, anomalous_windows=EXCLUDED.anomalous_windows,
            ai_anomaly_score=EXCLUDED.ai_anomaly_score, ai_evidence_json=EXCLUDED.ai_evidence_json,
            model_mode=EXCLUDED.model_mode, scored_at=EXCLUDED.scored_at,
            confidence=EXCLUDED.confidence, confidence_level=EXCLUDED.confidence_level,
            previous_ai_anomaly_score=EXCLUDED.previous_ai_anomaly_score, score_delta=EXCLUDED.score_delta,
            score_reason=EXCLUDED.score_reason, last_window_at=EXCLUDED.last_window_at,
            model_version=EXCLUDED.model_version""",
        (score["ip"], score["windows_seen"], score["anomalous_windows"], score["score"],
         Jsonb(score["evidence"]), MODEL_MODE, score["scored_at"], score["confidence"],
         score["confidence_level"], score["previous_score"], score["score_delta"], score["reason"],
         score["last_window_at"], score["model_version"]),
    )
    if old_tuple == new_tuple:
        return False
    append_ip_changes(conn, (score["ip"],), "ai", score["scored_at"])
    return True


def _finish_score_cycle(conn, now: datetime, max_event: int) -> None:
    """Persist the completed AI score cursor and commit its transaction."""
    scored_at = _iso(now)
    conn.execute(
        """UPDATE ai_model_state SET last_scored_event_id=%s, last_score_at=%s,
           last_score_status=%s, updated_at=%s WHERE model_key=%s""",
        (max_event, scored_at, "scored", scored_at, MODEL_KEY),
    )
    conn.commit()


def score_cycle(conn, force_full: bool = False) -> dict[str, Any]:
    """Orchestrate one bounded scoring cycle with the persisted model."""
    now = _utc_now()
    end = _floor_minute(now)
    start = end - timedelta(hours=_env_int("LOG_WS_AI_SCORE_LOOKBACK_HOURS", DEFAULT_SCORE_LOOKBACK_HOURS))
    bundle = load_model_bundle()
    base = {"model_mode": MODEL_MODE, "model_version": bundle.get("model_version") if bundle else None}
    if bundle is None:
        return {**base, "status": "model_unavailable", "ips": 0, "windows": 0, "anomalous_windows": 0}

    _state(conn)
    max_event = 0
    recent_cutoff = _iso(now - timedelta(minutes=10))
    if force_full:
        ip_rows = conn.execute(
            "SELECT DISTINCT host(ip) AS ip FROM ip_minute_features WHERE dataset_id=%s AND bucket_minute >= %s AND bucket_minute < %s",
            ("live", _iso(start), _iso(end)),
        ).fetchall()
    else:
        ip_rows = conn.execute(
            """SELECT DISTINCT host(ip) AS ip FROM ip_minute_features
               WHERE dataset_id=%s AND bucket_minute >= %s AND bucket_minute < %s""",
            ("live", recent_cutoff, _iso(end)),
        ).fetchall()
    ips = [row["ip"] for row in ip_rows]
    expired = expire_inactive_scores(conn, now)
    if not ips:
        _finish_score_cycle(conn, now, max_event)
        return {**base, "status": "scored", "ips": 0, "windows": 0, "anomalous_windows": 0, "expired": expired, "changed_ips": expired, "cursor": max_event}

    frame = _feature_frame(conn, start, end, ips)
    if frame.empty:
        _finish_score_cycle(conn, now, max_event)
        return {**base, "status": "scored", "ips": len(ips), "windows": 0, "anomalous_windows": 0, "expired": expired, "changed_ips": expired, "cursor": max_event}

    frame, anomaly_count = _score_windows(frame, bundle)
    scored_at = _iso(now)
    changed = 0
    for ip, group in frame.groupby("ip", sort=True):
        previous = conn.execute("SELECT * FROM ip_ai_scores WHERE ip = %s", (ip,)).fetchone()
        score = _build_ip_score(ip, group, previous, bundle, scored_at, force_full)
        changed += _persist_ip_score(conn, score, previous)

    _finish_score_cycle(conn, now, max_event)
    return {**base, "status": "scored", "ips": len(ips), "windows": len(frame), "anomalous_windows": anomaly_count, "changed_ips": changed + expired, "expired": expired, "cursor": max_event}


def score_import(conn) -> dict:
    """Backward-compatible entry point; never fits or clears persisted scores."""
    return score_cycle(conn, force_full=True)
