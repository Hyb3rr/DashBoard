from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from pathlib import Path
import asyncio
import ipaddress
import json
import time
from .config.settings import APP_DIR, SAMPLE_LOG
from .core.db import connect, decode, region_profile
from .core.logs import effective_risk, import_apache_lines
from .core.intelligence import classify_ip
from .tools.calibration import csv_text
from .services.profiles import (
    attach_region_and_classification,
    ai_profile_for_ip,
    classification_observation,
    ensure_profile,
)

app = FastAPI(title="Remote Web Monitoring Hub - IP Intelligence")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000", "null"],
    allow_origin_regex=r"^(null|https?://(localhost|127\.0\.0\.1)(:\d+)?)$",
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
@app.get("/", response_class=HTMLResponse)
def dashboard():
    """Serve dashboard and wire the existing Import sample button to file upload.

    This keeps dashboard.html unchanged: the injected script finds the existing
    button by its visible text, renames it to "Import log", opens a local file
    picker, and uploads the selected file to /api/import/log in replace mode.
    """
    html = (APP_DIR / "dashboard.html").read_text()
    upload_script = r"""
<script>
(() => {
  const installLogImporter = () => {
    const buttons = Array.from(document.querySelectorAll('button'));
    const importButton = buttons.find((button) => {
      const text = (button.textContent || '').trim().toLowerCase();
      return text === 'import sample' || text === 'import log';
    });

    if (!importButton || importButton.dataset.logImporterInstalled === '1') return;
    importButton.dataset.logImporterInstalled = '1';
    importButton.textContent = 'Import log';
    importButton.title = 'Upload a new Apache/Nginx log file';

    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.accept = '.log,.txt,text/plain';
    fileInput.style.display = 'none';
    document.body.appendChild(fileInput);

    const setButtonState = (text, disabled) => {
      importButton.textContent = text;
      importButton.disabled = disabled;
    };

    // Capture phase prevents the dashboard's old "Import sample" handler from
    // firing before/alongside this uploader.
    importButton.addEventListener('click', (event) => {
      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();
      fileInput.value = '';
      fileInput.click();
    }, true);

    fileInput.addEventListener('change', async () => {
      const file = fileInput.files && fileInput.files[0];
      if (!file) return;

      setButtonState('Uploading…', true);
      try {
        const url = `/api/import/log?filename=${encodeURIComponent(file.name)}&mode=replace`;
        const response = await fetch(url, {
          method: 'POST',
          headers: {'Content-Type': 'text/plain; charset=utf-8'},
          body: file,
        });

        let payload = null;
        try { payload = await response.json(); } catch (_) {}
        if (!response.ok) {
          const detail = payload && payload.detail ? payload.detail : `HTTP ${response.status}`;
          throw new Error(detail);
        }

        const count = payload && payload.unique_ips != null ? payload.unique_ips : '?';
        const ai = payload && payload.ai_scoring ? payload.ai_scoring : {};
        setButtonState(`Imported ${count} IPs · AI ${ai.status || 'unknown'} · mapping…`, true);

        // A replace import is a completely fresh test run. Start local-only
        // mapping immediately, highest-request IP first, and consume the NDJSON
        // stream so progress is visible instead of looking frozen.
        const mapResponse = await fetch('/api/ips/refresh-unknown?limit=5000', {
          method: 'POST',
          cache: 'no-store',
        });
        if (!mapResponse.ok || !mapResponse.body) {
          throw new Error(`Mapping failed: HTTP ${mapResponse.status}`);
        }

        const reader = mapResponse.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        let mapped = 0;
        let total = count;

        while (true) {
          const {value, done} = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, {stream: true});
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';
          for (const line of lines) {
            if (!line.trim()) continue;
            try {
              const item = JSON.parse(line);
              if (item.type === 'start') total = item.selected;
              if (item.type === 'ip') {
                mapped = item.index;
                setButtonState(`Mapping ${mapped}/${item.total}…`, true);
              }
              if (item.type === 'done') {
                setButtonState(`Done · ${item.processed} mapped`, true);
              }
            } catch (_) {}
          }
        }

        window.setTimeout(() => window.location.reload(), 350);
      } catch (error) {
        console.error('Log upload failed:', error);
        setButtonState('Upload failed', false);
        importButton.title = `Upload failed: ${error.message || error}`;
        window.setTimeout(() => setButtonState('Import log', false), 1800);
      }
    });
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', installLogImporter);
  } else {
    installLogImporter();
  }
})();
</script>
"""
    if "</body>" in html:
        html = html.replace("</body>", upload_script + "\n</body>", 1)
    else:
        html += upload_script
    return HTMLResponse(html)


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
        data["observation"] = obs_data
        data["effective_risk_score"], data["effective_risk_level"] = effective_risk(data.get("risk_score"), obs["behavior_score"])
        attach_region_and_classification(conn, data, obs_data)
    else:
        attach_region_and_classification(conn, data, None)
    conn.commit(); conn.close()
    return data


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
                   o.behavior_evidence_json
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
    limit = min(max(limit, 1), 500)
    conn = connect()
    rows = conn.execute("""
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
          COALESCE(o.requests, 0) AS requests,
          COALESCE(o.status_4xx, 0) AS status_4xx,
          COALESCE(o.status_5xx, 0) AS status_5xx,
          COALESCE(o.unique_paths, 0) AS unique_paths,
          COALESCE(o.wp_login_requests, 0) AS wp_login_requests,
          COALESCE(o.sensitive_probe_requests, 0) AS sensitive_probe_requests,
          o.first_seen, o.last_seen, p.fetched_at
        FROM ip_observations o
        LEFT JOIN ip_profiles p ON p.ip = o.ip
        UNION
        SELECT
          p.ip, p.country, p.country_code, p.city, p.region, p.latitude, p.longitude,
          p.timezone, p.asn, p.organization, p.isp,
          p.network_type, p.ip_prefix, p.organization_confidence, p.abuse_score, p.abuse_reports,
          p.is_hosting, p.is_vpn, p.is_proxy, p.is_tor,
          p.enrichment_status, p.core_enrichment_status, p.privacy_enrichment_status, p.threat_enrichment_status, p.next_retry_at,
          p.provider_status_json, p.field_sources_json,
          p.risk_score, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, p.fetched_at
        FROM ip_profiles p
        LEFT JOIN ip_observations o ON o.ip = p.ip
        WHERE o.ip IS NULL
        """).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item["provider_status"] = decode(item.pop("provider_status_json"))
        item["field_sources"] = decode(item.pop("field_sources_json"))
        item["effective_risk_score"], item["effective_risk_level"] = effective_risk(item["profile_risk_score"], item["behavior_score"])
        observation = {
            "behavior_score": item["behavior_score"],
            "requests": item["requests"],
            "status_4xx": item["status_4xx"],
            "status_5xx": item["status_5xx"],
            "unique_paths": item["unique_paths"],
            "wp_login_requests": item["wp_login_requests"],
            "sensitive_probe_requests": item["sensitive_probe_requests"],
        }
        attach_region_and_classification(conn, item, observation)
        items.append(item)
    conn.close()
    return sorted(items, key=lambda item: (item["threat_signal_score"], item["requests"]), reverse=True)[:limit]

def _import_summary(conn, result: dict, source: str, mode: str) -> dict:
    stats = conn.execute("""
        SELECT
          COUNT(*) AS unique_ips,
          COALESCE(SUM(requests), 0) AS observed_requests
        FROM ip_observations
    """).fetchone()
    not_enriched = conn.execute("""
        SELECT COUNT(*) AS n
        FROM ip_observations o
        LEFT JOIN ip_profiles p ON p.ip = o.ip
        WHERE p.ip IS NULL
           OR p.country IS NULL
           OR p.latitude IS NULL
           OR p.longitude IS NULL
    """).fetchone()["n"]
    result.update({
        "source": source,
        "mode": mode,
        "unique_ips": stats["unique_ips"],
        "observed_requests": stats["observed_requests"],
        "needs_local_mapping": not_enriched,
        "mapping_started": False,
    })
    return result


@app.post("/api/import/log")
async def import_log(request: Request, filename: str = "uploaded.log", mode: str = "replace"):
    """Import a new Apache/Nginx-style log without running enrichment.

    Send the file as the raw HTTP request body, for example:
      curl --data-binary @access.log "http://127.0.0.1:8000/api/import/log?filename=access.log&mode=replace"

    mode=replace performs a full test reset: events, observations, and cached
    ip_profiles are deleted so every IP in the new file is mapped again from
    scratch using the current local databases.
    mode=append adds new log lines to the current observations.
    """
    if mode not in {"replace", "append"}:
        raise HTTPException(400, "mode must be 'replace' or 'append'")

    body = await request.body()
    if not body:
        raise HTTPException(400, "Uploaded log is empty")
    if len(body) > 100 * 1024 * 1024:
        raise HTTPException(413, "Log file too large; maximum is 100 MiB")

    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        text = body.decode("utf-8", errors="replace")

    conn = connect()
    try:
        if mode == "replace":
            # Full reset for a brand-new test dataset.  Do not reuse enrichment
            # from the previous log: every observed IP will be mapped again.
            conn.execute("DELETE FROM events")
            conn.execute("DELETE FROM ip_observations")
            conn.execute("DELETE FROM ip_ai_scores")
            conn.execute("DELETE FROM ip_profiles")
            conn.commit()

        result = import_apache_lines(
            conn,
            text.splitlines(),
            source=Path(filename).name or "uploaded.log",
        )
        conn.commit()
        result = _import_summary(conn, result, Path(filename).name or "uploaded.log", mode)
        return result
    finally:
        conn.close()


@app.post("/api/import/sample")
async def import_sample(mode: str = "replace"):
    """Import the bundled apache_logs.log only. Mapping is deliberately separate."""
    if not SAMPLE_LOG.exists():
        raise HTTPException(404, "apache_logs.log not found")
    if mode not in {"replace", "append"}:
        raise HTTPException(400, "mode must be 'replace' or 'append'")

    conn = connect()
    try:
        if mode == "replace":
            conn.execute("DELETE FROM events")
            conn.execute("DELETE FROM ip_observations")
            conn.execute("DELETE FROM ip_ai_scores")
            conn.execute("DELETE FROM ip_profiles")
            conn.commit()

        with SAMPLE_LOG.open(errors="replace") as handle:
            result = import_apache_lines(conn, handle, source="apache_logs.log")
        conn.commit()
        return _import_summary(conn, result, "apache_logs.log", mode)
    finally:
        conn.close()
