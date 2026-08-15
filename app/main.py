from contextlib import asynccontextmanager

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
import asyncio
import ipaddress
import json
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from .config.settings import APP_DIR
from .core.db import connect, decode, region_profile
from .core.logs import effective_risk
from .core.intelligence import classify_ip
from .core.correlation import asn_clusters, cluster_for_ip
from .tools.calibration import csv_text
from .services.profiles import (
    attach_region_and_classification,
    ai_profile_for_ip,
    classification_observation,
    ensure_profile,
)
from .services.dispositions import set_disposition, STATES
from .collectors.websocket_collector import bus, collector


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await collector.start()
    try:
        yield
    finally:
        await collector.stop()


app = FastAPI(title="Remote Web Monitoring Hub - IP Intelligence", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=APP_DIR / "static"), name="static")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000", "null"],
    allow_origin_regex=r"^(null|https?://(localhost|127\.0\.0\.1)(:\d+)?)$",
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
@app.get("/", response_class=HTMLResponse)
def dashboard():
    return HTMLResponse((APP_DIR / "dashboard.html").read_text())


@app.get("/ip/{ip}", response_class=HTMLResponse)
def ip_case_page(ip: str):
    """Serve a stable full-page investigation view for one IP address."""
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise HTTPException(400, "Invalid IP address") from exc
    html = (APP_DIR / "ip_detail.html").read_text()
    return HTMLResponse(html)


@app.get("/regions", response_class=HTMLResponse)
def region_profiles_page():
    return HTMLResponse((APP_DIR / "regions.html").read_text())


@app.get("/regions/{country_code}", response_class=HTMLResponse)
def region_profile_page(country_code: str):
    """Serve the shell even for unknown codes so the page degrades cleanly."""
    return HTMLResponse((APP_DIR / "region_detail.html").read_text())

@app.get("/health")
def health():
    connect().close()
    return {"status": "ok", "mode": "read_only"}

@app.get("/api/analytics/traffic")
def traffic_analytics(range_key: str = Query("all", alias="range")):
    """Return a bounded traffic timeline and top access dimensions."""
    ranges = {
        "30m": (30 * 60, 5 * 60, "30 minutes"),
        "1h": (60 * 60, 10 * 60, "1 hour"),
        "6h": (6 * 60 * 60, 30 * 60, "6 hours"),
        "12h": (12 * 60 * 60, 60 * 60, "12 hours"),
        "1d": (24 * 60 * 60, 2 * 60 * 60, "1 day"),
        "3d": (3 * 24 * 60 * 60, 6 * 60 * 60, "3 days"),
        "7d": (7 * 24 * 60 * 60, 12 * 60 * 60, "7 days"),
        "30d": (30 * 24 * 60 * 60, 24 * 60 * 60, "30 days"),
    }
    selected = ranges.get(range_key)
    conn = connect()
    try:
        latest = conn.execute("SELECT MAX(timestamp) AS latest FROM events WHERE timestamp IS NOT NULL").fetchone()["latest"]
        if not latest:
            return {"series": [], "top_paths": [], "top_countries": [], "top_ips": [], "total_requests": 0, "range": range_key, "as_of": datetime.now(timezone.utc).isoformat()}
        try:
            latest_stamp = datetime.fromisoformat(str(latest).replace("Z", "+00:00"))
            if latest_stamp.tzinfo is None:
                latest_stamp = latest_stamp.replace(tzinfo=timezone.utc)
            latest_stamp = latest_stamp.astimezone(timezone.utc)
        except (TypeError, ValueError):
            latest_stamp = datetime.now(timezone.utc)

        where = "WHERE e.timestamp IS NOT NULL"
        params: list[str] = []
        if selected:
            range_seconds, bucket_seconds, range_label = selected
            latest_stamp = datetime.now(timezone.utc)
            start_stamp = latest_stamp - timedelta(seconds=range_seconds)
            where += " AND e.timestamp >= ? AND e.timestamp <= ?"
            params.extend([start_stamp.isoformat(), latest_stamp.isoformat()])
        else:
            range_label = "all available events"
        rows = conn.execute(
            f"""
            SELECT e.timestamp, e.src_ip, e.path, e.status, p.country_code, p.country
            FROM events e LEFT JOIN ip_profiles p ON p.ip = e.src_ip
            {where}
            ORDER BY e.timestamp ASC
            """,
            params,
        ).fetchall()
        parsed = []
        for row in rows:
            try:
                stamp = datetime.fromisoformat(str(row["timestamp"]).replace("Z", "+00:00"))
                if stamp.tzinfo is None:
                    stamp = stamp.replace(tzinfo=timezone.utc)
                parsed.append((stamp.astimezone(timezone.utc), row))
            except (TypeError, ValueError):
                continue
        if not parsed:
            return {"series": [], "top_paths": [], "top_countries": [], "top_ips": [], "total_requests": 0, "range": range_key, "range_label": range_label, "as_of": datetime.now(timezone.utc).isoformat()}
        if not selected:
            span_seconds = (parsed[-1][0] - parsed[0][0]).total_seconds()
            bucket_seconds = 3600 if span_seconds > 7 * 86400 else 900
            start_stamp = parsed[0][0]
            range_label = "all available events"
        bucket_count = max(1, (int((selected[0] if selected else max(1, (parsed[-1][0] - parsed[0][0]).total_seconds())) + bucket_seconds - 1) // bucket_seconds))
        grid_start = (start_stamp.timestamp() // bucket_seconds) * bucket_seconds
        bucket_starts = [datetime.fromtimestamp(grid_start + i * bucket_seconds, timezone.utc) for i in range(bucket_count)]
        buckets = {stamp.isoformat().replace("+00:00", "Z"): {"requests": 0, "errors": 0} for stamp in bucket_starts}
        paths, countries, ips = Counter(), Counter(), Counter()
        path_ips, country_ips = defaultdict(set), defaultdict(set)
        for stamp, row in parsed:
            index = int((stamp.timestamp() - grid_start) // bucket_seconds)
            index = max(0, min(bucket_count - 1, index))
            bucket = bucket_starts[index]
            item = buckets[bucket.isoformat().replace("+00:00", "Z")]
            item["requests"] += 1
            if int(row["status"] or 0) >= 400:
                item["errors"] += 1
            if row["path"]:
                path = str(row["path"])
                paths[path] += 1
                path_ips[path].add(str(row["src_ip"]))
            country = row["country_code"] or "Unknown"
            country_key = (str(country), str(row["country"] or country))
            countries[country_key] += 1
            country_ips[country_key].add(str(row["src_ip"]))
            ips[str(row["src_ip"])] += 1
        series = [{"timestamp": key, **buckets[key]} for key in buckets]
        return {
            "series": series,
            "bucket": f"{bucket_seconds // 60}min" if bucket_seconds < 3600 else f"{bucket_seconds // 3600}h",
            "range": range_key,
            "range_label": range_label,
            "top_paths": [{"path": key, "requests": value, "ips": sorted(path_ips[key])} for key, value in paths.most_common(8)],
            "top_countries": [{"country_code": key[0], "country": key[1], "requests": value, "ips": sorted(country_ips[key])} for key, value in countries.most_common(8)],
            "top_ips": [{"ip": key, "requests": value} for key, value in ips.most_common(8)],
            "total_requests": len(parsed),
            "as_of": datetime.now(timezone.utc).isoformat(),
        }
    finally:
        conn.close()

@app.get("/api/ip/{ip}/traffic")
def ip_traffic(ip: str, range_key: str = Query("1h", alias="range"), start: str | None = None, end: str | None = None):
    """Return one IP's complete traffic view from one filtered event set."""
    try:
        address = str(ipaddress.ip_address(ip))
    except ValueError as exc:
        raise HTTPException(400, "Invalid IP address") from exc
    ranges = {"30m": 1800, "1h": 3600, "6h": 21600, "12h": 43200, "1d": 86400, "3d": 259200, "7d": 604800}
    seconds = ranges.get(range_key, ranges["1h"])
    now = datetime.now(timezone.utc)
    end_stamp = _parse_traffic_time(end) if end else now
    start_stamp = _parse_traffic_time(start) if start else end_stamp - timedelta(seconds=seconds)
    if not start_stamp or not end_stamp or end_stamp <= start_stamp:
        raise HTTPException(400, "Invalid traffic time range")
    seconds = max(60, int((end_stamp - start_stamp).total_seconds()))
    bucket_seconds = max(60, min(3600, seconds // 12))
    conn = connect()
    try:
        rows = conn.execute(
            """SELECT timestamp, method, path, status, user_agent FROM events
               WHERE src_ip=? AND timestamp IS NOT NULL AND timestamp>=? AND timestamp<=?
               ORDER BY timestamp ASC""",
            (address, start_stamp.isoformat(), end_stamp.isoformat()),
        ).fetchall()
        parsed = []
        for row in rows:
            try:
                stamp = datetime.fromisoformat(str(row["timestamp"]).replace("Z", "+00:00"))
                if stamp.tzinfo is None: stamp = stamp.replace(tzinfo=timezone.utc)
                parsed.append((stamp.astimezone(timezone.utc), row))
            except (TypeError, ValueError):
                continue
        grid_start = datetime.fromtimestamp((start_stamp.timestamp() // bucket_seconds) * bucket_seconds, timezone.utc)
        bucket_count = max(1, int((end_stamp.timestamp() - grid_start.timestamp()) // bucket_seconds) + 1)
        bucket_starts = [grid_start + timedelta(seconds=i * bucket_seconds) for i in range(bucket_count)]
        buckets = {stamp.isoformat().replace("+00:00", "Z"): {"requests": 0, "errors": 0} for stamp in bucket_starts}
        status_codes = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}
        paths = Counter()
        for stamp, row in parsed:
            index = max(0, min(bucket_count - 1, int((stamp.timestamp() - grid_start.timestamp()) // bucket_seconds)))
            item = buckets[bucket_starts[index].isoformat().replace("+00:00", "Z")]
            item["requests"] += 1
            status = int(row["status"] or 0)
            family = f"{status // 100}xx"
            if family in status_codes: status_codes[family] += 1
            if status >= 400: item["errors"] += 1
            if row["path"]: paths[str(row["path"])] += 1
        recent = [
            {"timestamp": stamp.isoformat().replace("+00:00", "Z"), "method": row["method"] or "—",
             "path": row["path"] or "—", "status": row["status"]}
            for stamp, row in reversed(parsed[-50:])
        ]
        return {
            "ip": address, "range": range_key, "range_label": f"last {range_key}",
            "start": start_stamp.isoformat(), "end": end_stamp.isoformat(), "as_of": now.isoformat(),
            "total_requests": len(parsed), "series": [{"timestamp": key, **buckets[key]} for key in buckets],
            "status_codes": status_codes,
            "top_paths": [{"path": key, "requests": value} for key, value in paths.most_common(12)],
            "recent_requests": recent,
        }
    finally:
        conn.close()

def _parse_traffic_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None

@app.get("/api/ip/{ip}/paths")
def ip_path_activity(ip: str, limit: int = 12):
    """Return the most visited paths for one IP, without enrichment side effects."""
    try:
        address = str(ipaddress.ip_address(ip))
    except ValueError as exc:
        raise HTTPException(400, "Invalid IP address") from exc

    limit = min(max(limit, 1), 50)
    conn = connect()
    try:
        total = conn.execute(
            """SELECT COUNT(*) FROM events
               WHERE src_ip = ? AND path IS NOT NULL AND path != ''""",
            (address,),
        ).fetchone()[0]
        rows = conn.execute(
            """SELECT path,
                      COUNT(*) AS requests,
                      SUM(CASE WHEN COALESCE(status, 0) >= 400 THEN 1 ELSE 0 END) AS errors,
                      MIN(timestamp) AS first_seen,
                      MAX(timestamp) AS last_seen
                 FROM events
                WHERE src_ip = ? AND path IS NOT NULL AND path != ''
                GROUP BY path
                ORDER BY requests DESC, path ASC
                LIMIT ?""",
            (address, limit),
        ).fetchall()
        total = int(total or 0)
        paths = []
        for row in rows:
            item = dict(row)
            item["requests"] = int(item["requests"] or 0)
            item["errors"] = int(item["errors"] or 0)
            item["share"] = round(item["requests"] / total, 4) if total else 0
            paths.append(item)
        return {"ip": address, "total_requests": total, "paths": paths}
    finally:
        conn.close()


@app.get("/api/ip/{ip}")
async def ip_details(ip: str, refresh: bool = False):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise HTTPException(400, "Invalid IP address") from exc
    conn = connect()
    data, error = await ensure_profile(conn, str(address), refresh=refresh)
    if error:
        conn.close()
        raise HTTPException(502, f"Enrichment provider unavailable: {error}")
    obs = conn.execute("SELECT * FROM ip_observations WHERE ip = ?", (str(address),)).fetchone()
    if obs:
        obs_data = dict(obs)
        obs_data["behavior_evidence"] = decode(obs_data.pop("behavior_evidence_json"))
        obs_data["behavior_evidence_recent"] = decode(obs_data.pop("behavior_evidence_recent_json"))
        obs_data["detections"] = decode(obs_data.pop("detections_json", "[]"))
        data["observation"] = obs_data
        data["effective_risk_score"], data["effective_risk_level"] = effective_risk(data.get("risk_score"), obs["behavior_score"])
        attach_region_and_classification(conn, data, obs_data)
    else:
        attach_region_and_classification(conn, data, None)
    conn.commit(); conn.close()
    return data


@app.post("/api/ip/{ip}/disposition")
def update_ip_disposition(ip: str, payload: dict = Body(...)):
    try:
        address = str(ipaddress.ip_address(ip))
    except ValueError as exc:
        raise HTTPException(400, "Invalid IP address") from exc
    state = str(payload.get("state") or "").lower()
    if state not in STATES:
        raise HTTPException(400, "Invalid disposition state")
    conn = connect()
    try:
        row = conn.execute("SELECT * FROM ip_observations WHERE ip=?", (address,)).fetchone()
        profile = conn.execute("SELECT * FROM ip_profiles WHERE ip=?", (address,)).fetchone()
        label = None
        if row:
            item = dict(row)
            if profile:
                profile_data = dict(profile)
                label = classify_ip(profile_data, item).get("label")
        result = set_disposition(conn, address, state, payload.get("assigned_to"), payload.get("note"), payload.get("actor") or "system", label)
        return result
    finally:
        conn.close()


@app.get("/api/clusters")
def list_clusters(limit: int = 100):
    conn = connect()
    try:
        rows = conn.execute("SELECT * FROM ip_clusters ORDER BY campaign_score DESC, updated_at DESC LIMIT ?", (min(max(limit, 1), 500),)).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["member_ips"] = decode(item.pop("member_ips_json"))
            item["shared_paths"] = decode(item.pop("shared_paths_json"))
            items.append(item)
        return items
    finally:
        conn.close()


@app.get("/api/regions/demand-signal")
def region_demand_signal(limit: int = 50):
    """Aggregate observed, likely-legitimate traffic by country.

    This is an analyst signal, not a claim about individual identity or
    market demand.  It counts good-classified IPs with real requests while
    excluding privacy/hosting signals, bots, and sensitive probes, then joins
    the country profile's sourced context.
    """
    limit = min(max(limit, 1), 200)
    conn = connect()
    try:
        rows = conn.execute(
            """
            SELECT p.*, o.first_seen, o.last_seen, o.requests, o.status_4xx,
                   o.status_5xx, o.unique_paths, o.wp_login_requests,
                   o.sensitive_probe_requests, o.bot_requests, o.behavior_score,
                   o.behavior_score_recent, o.recent_requests, o.behavior_evidence_json,
                   o.behavior_evidence_recent_json
            FROM ip_profiles p
            LEFT JOIN ip_observations o ON o.ip = p.ip
            WHERE p.country_code IS NOT NULL
            """
        ).fetchall()
        aggregates = {}
        for raw in rows:
            item = dict(raw)
            item["identity_evidence"] = decode(item.pop("identity_evidence_json", "[]"))
            item["provider_errors"] = decode(item.pop("provider_errors_json", "[]"))
            item["provider_status"] = decode(item.pop("provider_status_json", "{}"))
            item["field_sources"] = decode(item.pop("field_sources_json", "{}"))
            item["reputation"] = decode(item.pop("reputation_json", "[]"))
            item["evidence"] = decode(item.pop("evidence_json", "[]"))
            item["sources"] = decode(item.pop("source_json", "[]"))
            item["behavior_evidence"] = decode(item.pop("behavior_evidence_json", "[]"))
            code = item["country_code"]
            region = region_profile(conn, code) or {"country_code": code, "country_name": item.get("country") or code}
            ai_profile = ai_profile_for_ip(conn, item.get("ip"))
            classification = classify_ip(item, classification_observation(item), region, ai_profile)
            entry = aggregates.setdefault(code, {
                "country_code": code,
                "country_name": region.get("country_name") or item.get("country") or code,
                "observed_ip_count": 0,
                "observed_requests": 0,
                "good_ip_count": 0,
                "classified_good_ip_count": 0,
                "good_requests": 0,
                "watch_ip_count": 0,
                "bad_ip_count": 0,
                "unknown_ip_count": 0,
                "privacy_signal_ip_count": 0,
                "profile_updated_at": region.get("updated_at"),
                "economic_indicators": region.get("economic_indicators", {}),
                "market_components": region.get("market_components", {}),
                "market_score": region.get("market_score"),
                "market_level": region.get("market_level", "unknown"),
                "product_opportunities": region.get("product_opportunities", []),
                "cultural_context": region.get("cultural_context", []),
                "conflict_indicators": region.get("conflict_indicators", []),
                "sources": region.get("sources", []),
            })
            requests = int(item.get("requests") or 0)
            label = classification["label"]
            entry["observed_ip_count"] += 1
            entry["observed_requests"] += requests
            if label == "good":
                entry["classified_good_ip_count"] += 1
            else:
                entry[f"{label}_ip_count"] += 1
            privacy_signal = any(item.get(field) == 1 for field in ("is_tor", "is_vpn", "is_proxy", "is_hosting"))
            if privacy_signal:
                entry["privacy_signal_ip_count"] += 1
            eligible = (
                label == "good" and requests > 0 and not privacy_signal
                and int(item.get("sensitive_probe_requests") or 0) == 0
                and int(item.get("bot_requests") or 0) == 0
            )
            if eligible:
                entry["good_requests"] += requests
                entry["good_ip_count"] += 1

        results = []
        for entry in aggregates.values():
            total = entry["observed_requests"]
            good_ips = entry["good_ip_count"]
            entry["good_traffic_share"] = round(entry["good_requests"] / total, 4) if total else 0
            entry["signal_level"] = (
                "high" if entry["good_requests"] >= 500 else
                "medium" if entry["good_requests"] >= 50 else
                "low" if entry["good_requests"] > 0 else "none"
            )
            entry["product_demand"] = (entry.get("market_components") or {}).get("product_demand")
            entry["analyst_note"] = "Observed good traffic signal; validate with conversion and customer data before market decisions." if good_ips else "No qualifying good traffic observed in the current window."
            results.append(entry)
        results.sort(key=lambda x: (x["good_requests"], x["observed_requests"]), reverse=True)
        return results[:limit]
    finally:
        conn.close()


@app.get("/api/regions/{country_code}")
def region_details(country_code: str):
    conn = connect()
    try:
        data = region_profile(conn, country_code.upper())
        if not data:
            raise HTTPException(404, "Region profile not found")
        return data
    finally:
        conn.close()


@app.get("/api/ips/calibration.csv", response_class=PlainTextResponse)
def calibration_export():
    """Export current predictions and signals for manual labeling."""
    return PlainTextResponse(
        csv_text(list_ips(limit=5000)),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=ip-calibration.csv"},
    )


@app.get("/api/regions")
def region_list(limit: int = 50):
    limit = min(max(limit, 1), 200)
    conn = connect()
    try:
        rows = conn.execute(
            """
            SELECT country_code, country_name, updated_at
            FROM region_profiles
            ORDER BY country_name ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            profile = region_profile(conn, row["country_code"])
            if profile:
                items.append(profile)
        return items
    finally:
        conn.close()

@app.post("/api/ips/refresh-unknown")
async def refresh_unknown(limit: int = 500):
    """Stream local-only enrichment results, highest-request IP first.

    Response format is NDJSON: one JSON object per line. Every IP is committed
    and yielded immediately after its local lookup finishes. No online provider
    is called by enrichment.lookup().
    """
    limit = min(max(limit, 1), 5000)

    # Select before streaming so the DB read cursor is not held for the whole run.
    select_conn = connect()
    rows = select_conn.execute("""
        SELECT
          o.ip AS ip,
          COALESCE(o.requests, 0) AS requests,
          p.core_enrichment_status,
          p.country, p.country_code, p.latitude, p.longitude
        FROM ip_observations o
        LEFT JOIN ip_profiles p ON p.ip = o.ip
        WHERE p.ip IS NULL
           OR p.core_enrichment_status IS NULL
           OR p.core_enrichment_status != 'complete'
           OR p.privacy_enrichment_status IS NULL
           OR p.privacy_enrichment_status != 'complete'
           OR p.country IS NULL OR p.country_code IS NULL
           OR p.latitude IS NULL OR p.longitude IS NULL
        ORDER BY COALESCE(o.requests, 0) DESC, o.ip ASC
        LIMIT ?
    """, (limit,)).fetchall()
    selected = [dict(row) for row in rows]
    select_conn.close()

    async def generate():
        yield json.dumps({
            "type": "start",
            "selected": len(selected),
            "mode": "local_only",
            "order": "requests_desc",
        }) + "\n"

        conn = connect()
        complete = partial = failed = processed = 0
        # Lookups are local disk/mmap reads (see enrichment.py), so several IPs
        # can genuinely be resolved at the same time instead of strictly one
        # after another. CHUNK_SIZE also sets how many rows share one
        # conn.commit(): committing every single IP was forcing a disk sync per
        # row, which dominated total mapping time far more than the lookups
        # themselves. Batching commits removes that overhead almost entirely
        # while still surfacing progress every CHUNK_SIZE rows.
        CHUNK_SIZE = 12
        try:
            for chunk_start in range(0, len(selected), CHUNK_SIZE):
                chunk = selected[chunk_start:chunk_start + CHUNK_SIZE]
                started = time.perf_counter()

                # Fire off this chunk's lookups concurrently; order of the
                # results list matches the order of `chunk` (asyncio.gather
                # guarantee), so priority order (highest requests first) is
                # preserved in the stream even though completion order inside
                # the chunk may vary.
                results = await asyncio.gather(*[
                    ensure_profile(conn, row["ip"], refresh=True) for row in chunk
                ])

                for offset, (row, (data, error)) in enumerate(zip(chunk, results)):
                    index = chunk_start + offset + 1
                    ip = row["ip"]
                    requests = row["requests"]
                    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)

                    if error:
                        failed += 1
                        payload = {
                            "type": "ip",
                            "index": index,
                            "total": len(selected),
                            "ip": ip,
                            "requests": requests,
                            "status": "failed",
                            "error": error,
                            "elapsed_ms": elapsed_ms,
                        }
                    else:
                        processed += 1
                        status = data.get("core_enrichment_status", "failed")
                        if status == "complete":
                            complete += 1
                        elif status == "partial":
                            partial += 1
                        else:
                            failed += 1

                        payload = {
                            "type": "ip",
                            "index": index,
                            "total": len(selected),
                            "ip": ip,
                            "requests": requests,
                            "status": status,
                            "country": data.get("country"),
                            "country_code": data.get("country_code"),
                            "region": data.get("region"),
                            "city": data.get("city"),
                            "latitude": data.get("latitude"),
                            "longitude": data.get("longitude"),
                            "asn": data.get("asn"),
                            "organization": data.get("organization"),
                            "sources": data.get("sources", []),
                            "provider_errors": data.get("provider_errors", []),
                            "elapsed_ms": elapsed_ms,
                        }

                    # One line becomes visible to curl/browser as soon as this IP finishes.
                    yield json.dumps(payload, ensure_ascii=False) + "\n"

                # One commit per chunk instead of one per IP.
                conn.commit()

            yield json.dumps({
                "type": "done",
                "selected": len(selected),
                "processed": processed,
                "complete": complete,
                "partial": partial,
                "failed": failed,
            }) + "\n"
        finally:
            conn.close()

    return StreamingResponse(
        generate(),
        media_type="application/x-ndjson",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )

@app.get("/api/ips")
def list_ips(limit: int = 100):
    conn = connect()
    try:
        return _build_ip_items(conn)[:min(max(limit, 1), 500)]
    finally:
        conn.close()


def _ip_rows(conn, only_ips: set[str] | None = None):
    first_where = ""
    second_where = "WHERE o.ip IS NULL"
    params: list[str] = []
    if only_ips:
        placeholders = ",".join("?" for _ in only_ips)
        values = sorted(only_ips)
        first_where = f"WHERE o.ip IN ({placeholders})"
        second_where = f"WHERE o.ip IS NULL AND p.ip IN ({placeholders})"
        params.extend(values)
        params.extend(values)
    return conn.execute(f"""
        SELECT
          COALESCE(o.ip, p.ip) AS ip,
          p.country, p.country_code, p.city, p.region, p.latitude, p.longitude,
          p.timezone, p.asn, p.organization, p.isp,
          p.network_type, p.ip_prefix, COALESCE(p.organization_confidence, 0) AS organization_confidence,
          p.abuse_score, p.abuse_reports,
          p.is_hosting, p.is_vpn, p.is_proxy, p.is_tor,
          p.enrichment_status, p.core_enrichment_status, p.privacy_enrichment_status, p.threat_enrichment_status, p.next_retry_at,
          p.provider_status_json, p.field_sources_json,
          COALESCE(p.risk_score, 0) AS profile_risk_score,
          COALESCE(o.behavior_score, 0) AS behavior_score,
          COALESCE(o.behavior_score_recent, 0) AS behavior_score_recent,
          COALESCE(o.requests, 0) AS requests,
          COALESCE(o.recent_requests, 0) AS recent_requests,
          COALESCE(o.recent_sensitive_probe_requests, 0) AS recent_sensitive_probe_requests,
          o.recent_first_seen AS recent_first_seen,
          o.recent_updated_at AS recent_updated_at,
          COALESCE(o.status_4xx, 0) AS status_4xx,
          COALESCE(o.status_5xx, 0) AS status_5xx,
          COALESCE(o.unique_paths, 0) AS unique_paths,
          COALESCE(o.wp_login_requests, 0) AS wp_login_requests,
          COALESCE(o.sensitive_probe_requests, 0) AS sensitive_probe_requests,
          o.first_seen, o.last_seen, p.fetched_at
        FROM ip_observations o
        LEFT JOIN ip_profiles p ON p.ip = o.ip
        {first_where}
        UNION
        SELECT
          p.ip, p.country, p.country_code, p.city, p.region, p.latitude, p.longitude,
          p.timezone, p.asn, p.organization, p.isp,
          p.network_type, p.ip_prefix, p.organization_confidence, p.abuse_score, p.abuse_reports,
          p.is_hosting, p.is_vpn, p.is_proxy, p.is_tor,
          p.enrichment_status, p.core_enrichment_status, p.privacy_enrichment_status, p.threat_enrichment_status, p.next_retry_at,
          p.provider_status_json, p.field_sources_json,
          p.risk_score, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, p.fetched_at
        FROM ip_profiles p
        LEFT JOIN ip_observations o ON o.ip = p.ip
        {second_where}
        """, params).fetchall()


def _build_ip_items(conn, only_ips: set[str] | None = None):
    rows = _ip_rows(conn, only_ips)
    items = []
    for row in rows:
        item = dict(row)
        item["provider_status"] = decode(item.pop("provider_status_json"))
        item["field_sources"] = decode(item.pop("field_sources_json"))
        item["effective_risk_score"], item["effective_risk_level"] = effective_risk(item["profile_risk_score"], item["behavior_score"])
        observation = {
            "behavior_score": item["behavior_score"],
            "recent_behavior_score": item["behavior_score_recent"] if item["recent_updated_at"] else item["behavior_score"],
            "requests": item["requests"],
            "recent_requests": item["recent_requests"] if item["recent_updated_at"] else item["requests"],
            "recent_sensitive_probe_requests": item["recent_sensitive_probe_requests"] if item["recent_updated_at"] else item["sensitive_probe_requests"],
            "recent_first_seen": item["recent_first_seen"],
            "status_4xx": item["status_4xx"],
            "status_5xx": item["status_5xx"],
            "unique_paths": item["unique_paths"],
            "wp_login_requests": item["wp_login_requests"],
            "sensitive_probe_requests": item["sensitive_probe_requests"],
        }
        attach_region_and_classification(conn, item, observation)
        items.append(item)
    return sorted(items, key=lambda item: (item["threat_signal_score"], item["requests"]), reverse=True)


def _change_cursor(conn) -> int:
    return int(conn.execute("SELECT COALESCE(MAX(seq), 0) AS seq FROM ip_change_log").fetchone()["seq"])


@app.get("/api/ips/snapshot")
def ip_snapshot(limit: int = 500):
    conn = connect()
    try:
        return {
            "items": _build_ip_items(conn)[:min(max(limit, 1), 500)],
            "cursor": _change_cursor(conn),
            "snapshot_at": datetime.now(timezone.utc).isoformat(),
        }
    finally:
        conn.close()


@app.get("/api/ips/updates")
def ip_updates(after: int = 0, limit: int = 500):
    limit = min(max(limit, 1), 500)
    conn = connect()
    try:
        current = _change_cursor(conn)
        oldest_row = conn.execute("SELECT MIN(seq) AS seq FROM ip_change_log").fetchone()
        oldest = int(oldest_row["seq"] or 0)
        if after and oldest and after < oldest - 1:
            return {"items": [], "cursor": current, "has_more": False, "reset_required": True}
        changed = conn.execute(
            "SELECT seq, ip FROM ip_change_log WHERE seq > ? ORDER BY seq LIMIT ?",
            (after, limit + 1),
        ).fetchall()
        has_more = len(changed) > limit
        delivered = changed[:limit]
        ips = {row["ip"] for row in delivered}
        next_cursor = int(delivered[-1]["seq"]) if has_more and delivered else current
        return {
            "items": _build_ip_items(conn, ips),
            "cursor": next_cursor,
            "has_more": has_more,
            "reset_required": False,
        }
    finally:
        conn.close()


@app.get("/api/collector/status")
def collector_status():
    payload = collector.status()
    conn = connect()
    try:
        row = conn.execute("SELECT * FROM ai_model_state WHERE model_key = 'isolation_forest_v1'").fetchone()
        if row:
            payload.update({
                "ai_model_version": row["model_version"],
                "ai_trained_at": row["trained_at"],
                "ai_train_status": row["last_train_status"],
                "ai_training_windows": row["training_windows"],
                "ai_last_score_at": row["last_score_at"],
                "ai_score_status": row["last_score_status"],
                "ai_last_error": row["last_train_error"],
            })
        return payload
    finally:
        conn.close()


@app.get("/api/stream")
async def realtime_stream():
    async def generate():
        iterator = bus.subscribe().__aiter__()
        try:
            while True:
                try:
                    event, payload = await asyncio.wait_for(iterator.__anext__(), timeout=15)
                    yield f"event: {event}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
        except (asyncio.CancelledError, StopAsyncIteration):
            return
        finally:
            await iterator.aclose()

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
