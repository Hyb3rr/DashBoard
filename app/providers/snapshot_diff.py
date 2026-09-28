"""Set-based snapshot diff application for PostgreSQL intelligence feeds."""
from __future__ import annotations

import csv
import io
import json
import os
import time
import uuid
from datetime import datetime, timezone

from psycopg.types.json import Jsonb


class SnapshotRejected(RuntimeError):
    """Raised when a snapshot safety gate rejects a provider refresh."""

    def __init__(self, result):
        """Keep the rejected snapshot result available to the provider runner."""
        self.result = result
        super().__init__(result.get("error", "snapshot rejected"))


def _now():
    """Return the current timestamp in UTC."""
    return datetime.now(timezone.utc)


def _source_env(source: str, suffix: str) -> str:
    """Read a provider-specific snapshot setting from the environment."""
    normalized = "".join(char if char.isalnum() else "_" for char in source.upper())
    return os.getenv(f"INTEL_SNAPSHOT_{normalized}_{suffix}", "").strip()


def _timings(started, *, parse_ms=0.0, copy_ms=0.0, stage_index_ms=0.0,
             analyze_ms=0.0, diff_ms=0.0, apply_ms=0.0, history_ms=0.0):
    """Build the stable timing fields shared by snapshot refresh results."""
    return {
        "parse_ms": round(parse_ms, 2),
        "copy_ms": round(copy_ms, 2),
        "stage_index_ms": round(stage_index_ms, 2),
        "analyze_ms": round(analyze_ms, 2),
        "diff_ms": round(diff_ms, 2),
        "apply_ms": round(apply_ms, 2),
        "history_ms": round(history_ms, 2),
        "total_ms": round((time.monotonic() - started) * 1000, 2),
    }


def _write_snapshot_stage(cur, target, rows, is_privacy):
    """Copy normalized provider rows into an indexed temporary snapshot table."""
    stage = f"{target}_snapshot_stage"
    cur.execute(f"DROP TABLE IF EXISTS {stage}")
    cur.execute(f"""CREATE TEMP TABLE {stage} (
        network CIDR NOT NULL,
        provider TEXT,
        proxy_type TEXT,
        score DOUBLE PRECISION,
        metadata JSONB NOT NULL
    ) ON COMMIT DROP""")

    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    snapshot_rows = 0
    for row in rows:
        if is_privacy:
            network, _row_kind, provider, proxy_type, score, _row_source, *_rest, metadata = row
            provider_value = provider or "\\N"
            proxy_value = proxy_type or "\\N"
            metadata_value = metadata.obj if isinstance(metadata, Jsonb) else (metadata or {})
        else:
            network = row
            provider_value = "\\N"
            proxy_value = "\\N"
            score = 1.0
            metadata_value = {}
        writer.writerow((
            network,
            provider_value,
            proxy_value,
            "\\N" if score is None else score,
            json.dumps(metadata_value, separators=(",", ":")),
        ))
        snapshot_rows += 1

    buffer.seek(0)
    copy_started = time.monotonic()
    with cur.copy(f"COPY {stage}(network,provider,proxy_type,score,metadata) FROM STDIN WITH (FORMAT CSV, NULL '\\N')") as copy:
        copy.write(buffer.read())
    copy_ms = (time.monotonic() - copy_started) * 1000

    index_started = time.monotonic()
    cur.execute(f"CREATE UNIQUE INDEX {stage}_network_idx ON {stage}(network)")
    stage_index_ms = (time.monotonic() - index_started) * 1000

    analyze_started = time.monotonic()
    cur.execute(f"ANALYZE {stage}")
    analyze_ms = (time.monotonic() - analyze_started) * 1000
    return stage, snapshot_rows, {
        "copy_ms": copy_ms,
        "stage_index_ms": stage_index_ms,
        "analyze_ms": analyze_ms,
    }


def _shrink_limits(source):
    """Resolve source-specific snapshot size limits with safe defaults."""
    try:
        configured_ratio = _source_env(source, "MAX_SHRINK_RATIO") or os.getenv(
            "INTEL_SNAPSHOT_MAX_SHRINK_RATIO",
            os.getenv("INTEL_SNAPSHOT_MIN_RATIO", "0.5"),
        )
        minimum_ratio = max(0.0, min(1.0, 1.0 - float(configured_ratio)))
        minimum_rows = max(0, int(_source_env(source, "MIN_ROWS") or os.getenv("INTEL_SNAPSHOT_MIN_ROWS", "0")))
    except (TypeError, ValueError):
        minimum_ratio, minimum_rows = 0.5, 0
    return minimum_ratio, minimum_rows


def _snapshot_change_counts(cur, stage, table, scope_column, source, discriminator,
                            compare_current, compare_stage, snapshot_rows, current_active):
    """Count added, changed, removed, reactivated, and unchanged current rows."""
    args = (source, discriminator)
    diff_started = time.monotonic()
    summary = cur.execute(f"""SELECT
          count(*) FILTER (WHERE p.network IS NULL),
          count(*) FILTER (WHERE p.network IS NOT NULL AND NOT p.active),
          count(*) FILTER (WHERE p.network IS NOT NULL AND p.active AND
            {compare_current} IS DISTINCT FROM {compare_stage}),
          count(*) FILTER (WHERE p.network IS NOT NULL AND p.active AND
            {compare_current} IS NOT DISTINCT FROM {compare_stage})
        FROM {stage} s
        LEFT JOIN {table} p
          ON p.source=%s AND p.{scope_column}=%s AND p.network=s.network""", args).fetchone()
    added, reactivated, changed, unchanged = (int(value or 0) for value in summary)
    if snapshot_rows == current_active and not (added or reactivated or changed):
        removed = 0
    else:
        removed = cur.execute(f"""SELECT count(*) FROM {table} p
            WHERE p.source=%s AND p.{scope_column}=%s AND p.active
              AND NOT EXISTS (SELECT 1 FROM {stage} s WHERE s.network=p.network)""", args).fetchone()[0]
    return {
        "added": added,
        "reactivated": reactivated,
        "changed": changed,
        "unchanged": unchanged,
        "removed": int(removed or 0),
        "diff_ms": (time.monotonic() - diff_started) * 1000,
    }


def _write_privacy_history(cur, stage, source, discriminator, now, refresh_id):
    """Append only privacy membership changes to the delta-history table."""
    history_started = time.monotonic()
    cur.execute(f"""INSERT INTO privacy_network_change_history
        (changed_at,source,kind,network,change_type,old_state,new_state,refresh_id)
        SELECT %s,%s,%s,s.network,
          CASE WHEN p.network IS NULL THEN 'added'
               WHEN NOT p.active THEN 'reactivated' ELSE 'changed' END,
          CASE WHEN p.network IS NULL THEN NULL ELSE to_jsonb(p) END,
          jsonb_build_object('provider',s.provider,'proxy_type',s.proxy_type,
            'score',s.score,'metadata',s.metadata,'active',true),
          %s
        FROM {stage} s
        LEFT JOIN privacy_networks p ON p.source=%s AND p.kind=%s AND p.network=s.network
        WHERE p.network IS NULL OR NOT p.active OR
          (p.provider,p.proxy_type,p.score,p.metadata) IS DISTINCT FROM
          (s.provider,s.proxy_type,s.score,s.metadata)""",
        (now, source, discriminator, refresh_id, source, discriminator))
    cur.execute(f"""INSERT INTO privacy_network_change_history
        (changed_at,source,kind,network,change_type,old_state,new_state,refresh_id)
        SELECT %s,%s,p.kind,p.network,'removed',to_jsonb(p),NULL,%s
        FROM privacy_networks p
        WHERE p.source=%s AND p.kind=%s AND p.active
          AND NOT EXISTS (SELECT 1 FROM {stage} s WHERE s.network=p.network)""",
        (now, source, refresh_id, source, discriminator))
    return (time.monotonic() - history_started) * 1000


def _apply_current_snapshot(cur, stage, table, scope_column, source, discriminator,
                            is_privacy, now):
    """Upsert changed memberships and deactivate entries missing from the snapshot."""
    apply_started = time.monotonic()
    if is_privacy:
        cur.execute(f"""INSERT INTO privacy_networks
            (network,kind,provider,proxy_type,score,source,first_seen,last_seen,checked_at,metadata,active)
            SELECT network,%s,provider,proxy_type,score,%s,%s,%s,%s,metadata,true
            FROM {stage}
            ON CONFLICT(source,kind,network) DO UPDATE SET
              provider=EXCLUDED.provider, proxy_type=EXCLUDED.proxy_type,
              score=EXCLUDED.score, last_seen=EXCLUDED.last_seen,
              checked_at=EXCLUDED.checked_at, metadata=EXCLUDED.metadata, active=true
            WHERE privacy_networks.active IS DISTINCT FROM true OR
              (privacy_networks.provider,privacy_networks.proxy_type,
               privacy_networks.score,privacy_networks.metadata) IS DISTINCT FROM
              (EXCLUDED.provider,EXCLUDED.proxy_type,EXCLUDED.score,EXCLUDED.metadata)""",
            (discriminator, source, now, now, now))
    else:
        cur.execute(f"""INSERT INTO threat_indicators
            (network,source,category,confidence,first_seen,last_seen,checked_at,evidence,active)
            SELECT network,%s,%s,score,now(),now(),now(),metadata,true
            FROM {stage}
            ON CONFLICT(network,source,category) DO UPDATE SET
              confidence=EXCLUDED.confidence, last_seen=EXCLUDED.last_seen,
              checked_at=EXCLUDED.checked_at, evidence=EXCLUDED.evidence, active=true
            WHERE threat_indicators.active IS DISTINCT FROM true OR
              (threat_indicators.confidence,threat_indicators.evidence) IS DISTINCT FROM
              (EXCLUDED.confidence,EXCLUDED.evidence)""", (source, discriminator))
    inserted_or_updated = cur.rowcount
    cur.execute(f"""UPDATE {table} p SET active=false
        WHERE p.source=%s AND p.{scope_column}=%s AND p.active
          AND NOT EXISTS (SELECT 1 FROM {stage} s WHERE s.network=p.network)""",
        (source, discriminator))
    current_rows_written = inserted_or_updated + cur.rowcount
    return current_rows_written, (time.monotonic() - apply_started) * 1000


def _snapshot_result(status, started, snapshot_rows, *, fields=None, timings=None):
    """Build the common snapshot result envelope with phase timings."""
    result = {
        "status": status,
        "snapshot_rows": snapshot_rows,
        "records_upserted": snapshot_rows,
    }
    result.update(fields or {})
    result.update(_timings(started, **(timings or {})))
    return result


def _snapshot_comparison_columns(is_privacy):
    """Return current and staged fields used to detect meaningful changes."""
    if is_privacy:
        return "(p.provider,p.proxy_type,p.score,p.metadata)", "(s.provider,s.proxy_type,s.score,s.metadata)"
    return "(p.confidence,p.evidence)", "(s.score,s.metadata)"


def _stage_and_validate_snapshot(cur, source, discriminator, rows, target, table, started):
    """Stage a snapshot and reject empty or suspiciously small input safely."""
    is_privacy = target == "privacy"
    stage, snapshot_rows, stage_timings = _write_snapshot_stage(cur, target, rows, is_privacy)
    timings = dict(stage_timings)
    if snapshot_rows == 0:
        return None, _snapshot_result("failed", started, 0, fields={
            "error": "empty snapshot rejected", "current_rows_written": 0,
            "history_rows_written": 0,
        }, timings=timings)

    scope_column = "kind" if is_privacy else "category"
    current_active = cur.execute(
        f"SELECT count(*) FROM {table} WHERE source=%s AND {scope_column}=%s AND active",
        (source, discriminator),
    ).fetchone()[0]
    minimum_ratio, minimum_rows = _shrink_limits(source)
    if (current_active and snapshot_rows < current_active * minimum_ratio) or snapshot_rows < minimum_rows:
        return None, _snapshot_result("failed", started, snapshot_rows, fields={
            "error": "snapshot unexpectedly smaller than active baseline",
            "current_active_rows": current_active,
            "minimum_ratio": minimum_ratio,
            "minimum_rows": minimum_rows,
            "records_upserted": 0,
            "current_rows_written": 0,
            "history_rows_written": 0,
        }, timings=timings)
    return {
        "stage": stage,
        "snapshot_rows": snapshot_rows,
        "scope_column": scope_column,
        "current_active": current_active,
        "timings": timings,
    }, None


def _compare_staged_snapshot(cur, staged, source, discriminator, table, is_privacy):
    """Count snapshot changes using the configured target-specific fields."""
    current_fields, staged_fields = _snapshot_comparison_columns(is_privacy)
    changes = _snapshot_change_counts(
        cur, staged["stage"], table, staged["scope_column"], source, discriminator,
        current_fields, staged_fields, staged["snapshot_rows"], staged["current_active"],
    )
    staged["timings"]["diff_ms"] = changes["diff_ms"]
    return changes


def _persist_snapshot_delta(cur, staged, changes, source, discriminator,
                            is_privacy, history, now, refresh_id, table):
    """Write privacy change history and apply the current-state delta."""
    history_ms = 0.0
    if is_privacy and history:
        history_ms = _write_privacy_history(
            cur, staged["stage"], source, discriminator, now, refresh_id
        )
    current_rows_written, apply_ms = _apply_current_snapshot(
        cur, staged["stage"], table, staged["scope_column"], source,
        discriminator, is_privacy, now,
    )
    change_count = sum(changes[key] for key in ("added", "changed", "removed", "reactivated"))
    return {
        "current_rows_written": current_rows_written,
        "history_rows_written": change_count if is_privacy and history else 0,
        "apply_ms": apply_ms,
        "history_ms": history_ms,
    }


def _apply_snapshot(conn, source, discriminator, rows, *, target, history):
    """Shared staging/diff/apply engine for privacy and threat snapshots."""
    table_by_target = {"privacy": "privacy_networks", "threat": "threat_indicators"}
    if target not in table_by_target:
        raise ValueError(f"unsupported snapshot target: {target}")
    is_privacy = target == "privacy"
    table = table_by_target[target]
    started = time.monotonic()
    now = _now()
    refresh_id = str(uuid.uuid4())
    copy_ms = stage_index_ms = analyze_ms = diff_ms = history_ms = apply_ms = 0.0

    with conn.cursor() as cur:
        staged, rejection = _stage_and_validate_snapshot(
            cur, source, discriminator, rows, target, table, started
        )
        if rejection:
            return rejection
        changes = _compare_staged_snapshot(cur, staged, source, discriminator, table, is_privacy)
        change_fields = {key: changes[key] for key in ("added", "changed", "removed", "reactivated", "unchanged")}
        if not any(change_fields[key] for key in ("added", "changed", "removed", "reactivated")):
            return _snapshot_result("updated", started, staged["snapshot_rows"], fields={
                **change_fields, "current_rows_written": 0, "history_rows_written": 0,
            }, timings=staged["timings"])
        writes = _persist_snapshot_delta(
            cur, staged, changes, source, discriminator, is_privacy,
            history, now, refresh_id, table,
        )

    staged["timings"].update(apply_ms=writes["apply_ms"], history_ms=writes["history_ms"])
    return _snapshot_result("updated", started, staged["snapshot_rows"], fields={
        **change_fields,
        "current_rows_written": writes["current_rows_written"],
        "history_rows_written": writes["history_rows_written"],
    }, timings=staged["timings"])


def apply_privacy_snapshot(conn, source, kind, rows, *, history=True):
    """Apply one privacy-network snapshot and optional change history."""
    return _apply_snapshot(conn, source, kind, rows, target="privacy", history=history)


def apply_threat_snapshot(conn, source, category, networks):
    """Apply one threat-indicator snapshot without privacy history."""
    return _apply_snapshot(conn, source, category, networks, target="threat", history=False)


def _write_geo_snapshot_stage(cur, rows, stage):
    """Create, populate, index, and analyze the temporary RIR snapshot table."""
    cur.execute(f"DROP TABLE IF EXISTS {stage}")
    cur.execute(f"""CREATE TEMP TABLE {stage} (
        network CIDR NOT NULL, rir TEXT,
        registration_country TEXT, metadata JSONB NOT NULL
    ) ON COMMIT DROP""")
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    for row in rows:
        writer.writerow((row["network"], row.get("rir"), row.get("country_code"),
                         json.dumps(row.get("metadata") or {}, separators=(",", ":"))))
    buffer.seek(0)
    copy_started = time.monotonic()
    with cur.copy(f"COPY {stage}(network,rir,registration_country,metadata) FROM STDIN WITH (FORMAT CSV)") as copy:
        copy.write(buffer.read())
    copy_ms = (time.monotonic() - copy_started) * 1000
    index_started = time.monotonic()
    cur.execute(f"CREATE UNIQUE INDEX {stage}_network_idx ON {stage}(network)")
    stage_index_ms = (time.monotonic() - index_started) * 1000
    analyze_started = time.monotonic()
    cur.execute(f"ANALYZE {stage}")
    analyze_ms = (time.monotonic() - analyze_started) * 1000
    return {"copy_ms": copy_ms, "stage_index_ms": stage_index_ms, "analyze_ms": analyze_ms}


def _geo_snapshot_changes(cur, stage, source):
    """Count RIR additions, changes, removals, and reactivations for a source."""
    diff_started = time.monotonic()
    counts = cur.execute(f"""SELECT
        count(*) FILTER (WHERE p.network IS NULL),
        count(*) FILTER (WHERE p.network IS NOT NULL AND NOT p.active),
        count(*) FILTER (WHERE p.network IS NOT NULL AND p.active AND
          (p.rir,p.registration_country,p.metadata) IS DISTINCT FROM
          (s.rir,s.registration_country,s.metadata)),
        count(*) FILTER (WHERE p.network IS NOT NULL AND p.active AND
          (p.rir,p.registration_country,p.metadata) IS NOT DISTINCT FROM
          (s.rir,s.registration_country,s.metadata))
      FROM {stage} s LEFT JOIN geo_prefixes p
        ON p.source=%s AND p.network=s.network""", (source,)).fetchone()
    added, reactivated, changed, unchanged = (int(value or 0) for value in counts)
    removed = cur.execute(f"""SELECT count(*) FROM geo_prefixes p
      WHERE p.source=%s AND p.active
        AND NOT EXISTS (SELECT 1 FROM {stage} s WHERE s.network=p.network)""", (source,)).fetchone()[0]
    return {
        "added": added,
        "reactivated": reactivated,
        "changed": changed,
        "unchanged": unchanged,
        "removed": int(removed or 0),
        "diff_ms": (time.monotonic() - diff_started) * 1000,
    }


def _apply_geo_snapshot_changes(cur, stage, source, now):
    """Upsert changed RIR prefixes and deactivate prefixes missing from the snapshot."""
    apply_started = time.monotonic()
    cur.execute(f"""INSERT INTO geo_prefixes
      (network,rir,registration_country,source,first_seen,last_seen,active,metadata)
      SELECT network,rir,registration_country,%s,%s,%s,true,metadata FROM {stage}
      ON CONFLICT(network,source) DO UPDATE SET
        rir=EXCLUDED.rir, registration_country=EXCLUDED.registration_country,
        last_seen=EXCLUDED.last_seen, active=true, metadata=EXCLUDED.metadata
      WHERE geo_prefixes.active IS DISTINCT FROM true OR
        (geo_prefixes.rir,geo_prefixes.registration_country,geo_prefixes.metadata) IS DISTINCT FROM
        (EXCLUDED.rir,EXCLUDED.registration_country,EXCLUDED.metadata)""", (source, now, now))
    inserted_or_updated = cur.rowcount
    cur.execute(f"""UPDATE geo_prefixes p SET active=false
      WHERE p.source=%s AND p.active
        AND NOT EXISTS (SELECT 1 FROM {stage} s WHERE s.network=p.network)""", (source,))
    return inserted_or_updated + cur.rowcount, (time.monotonic() - apply_started) * 1000


def apply_geo_snapshot(conn, source, rows):
    """Apply a RIR prefix snapshot using (network, source) identity."""
    started = time.monotonic()
    rows = list(rows)
    stage = "geo_snapshot_stage"
    with conn.cursor() as cur:
        timings = _write_geo_snapshot_stage(cur, rows, stage)
        if not rows:
            return {
                "status": "failed", "error": "empty snapshot rejected", "snapshot_rows": 0,
                "current_rows_written": 0, "added": 0, "changed": 0, "removed": 0,
                "reactivated": 0, **{key: round(value, 2) for key, value in timings.items()},
                "total_ms": round((time.monotonic() - started) * 1000, 2),
            }

        source_count = cur.execute(
            "SELECT count(*) FROM geo_prefixes WHERE source=%s AND active", (source,)
        ).fetchone()[0]
        minimum_ratio, minimum_rows = _shrink_limits(source)
        if (source_count and len(rows) < source_count * minimum_ratio) or len(rows) < minimum_rows:
            return {
                "status": "failed", "error": "snapshot unexpectedly smaller than active baseline",
                "snapshot_rows": len(rows), "current_active_rows": int(source_count),
                "minimum_ratio": minimum_ratio, "minimum_rows": minimum_rows,
                "current_rows_written": 0, "added": 0, "changed": 0, "removed": 0,
                "reactivated": 0, **{key: round(value, 2) for key, value in timings.items()},
                "total_ms": round((time.monotonic() - started) * 1000, 2),
            }

        changes = _geo_snapshot_changes(cur, stage, source)
        result = {
            "status": "updated", "snapshot_rows": len(rows), "records_upserted": len(rows),
            "added": changes["added"], "changed": changes["changed"],
            "removed": changes["removed"], "reactivated": changes["reactivated"],
            "unchanged": changes["unchanged"], "current_rows_written": 0,
            **{key: round(value, 2) for key, value in timings.items()},
            "diff_ms": round(changes["diff_ms"], 2),
        }
        if not any(changes[key] for key in ("added", "changed", "removed", "reactivated")):
            result.update({"apply_ms": 0.0, "total_ms": round((time.monotonic() - started) * 1000, 2)})
            return result

        written, apply_ms = _apply_geo_snapshot_changes(cur, stage, source, _now())
        result["current_rows_written"] = written
        result["apply_ms"] = round(apply_ms, 2)
        result["total_ms"] = round((time.monotonic() - started) * 1000, 2)
        return result
