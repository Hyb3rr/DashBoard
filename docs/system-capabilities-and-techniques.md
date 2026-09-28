# Sentinel Hub — Chức năng và kỹ thuật

> Tài liệu này tổng hợp chức năng, data flow và kỹ thuật đang được triển khai trong repository. Bố cục bám theo [README](../README.md), nhưng mô tả chi tiết hơn và chỉ rõ khu vực source liên quan. Khi tài liệu và runtime khác nhau, code/config hiện hành là nguồn chuẩn.

## Mục lục

- [1. Tổng quan](#1-tổng-quan)
- [2. Tech stack và quyền sở hữu dữ liệu](#2-tech-stack-và-quyền-sở-hữu-dữ-liệu)
- [3. Kiến trúc và luồng dữ liệu](#3-kiến-trúc-và-luồng-dữ-liệu)
- [4. Collector, độ bền và raw log](#4-collector-độ-bền-và-raw-log)
- [5. Chuẩn hóa và lưu trữ](#5-chuẩn-hóa-và-lưu-trữ)
- [6. Detection, scoring và evidence](#6-detection-scoring-và-evidence)
- [7. Threat intelligence và enrichment](#7-threat-intelligence-và-enrichment)
- [8. Alerts và điều tra](#8-alerts-và-điều-tra)
- [9. Region / Market Intelligence](#9-region--market-intelligence)
- [10. API, SSE và giao diện](#10-api-sse-và-giao-diện)
- [11. Local AI Reasoner](#11-local-ai-reasoner)
- [12. Workers, scheduler và vận hành](#12-workers-scheduler-và-vận-hành)
- [13. Backup, restore và retention](#13-backup-restore-và-retention)
- [14. Security và ranh giới sản phẩm](#14-security-và-ranh-giới-sản-phẩm)
- [15. Test và kiểm chứng](#15-test-và-kiểm-chứng)
- [16. Những điều hệ thống không làm](#16-những-điều-hệ-thống-không-làm)

## 1. Tổng quan

Sentinel Hub là hệ thống **giám sát web server theo hướng read-only**. Máy chủ được theo dõi chỉ gửi log; Sentinel Hub nhận telemetry, phân tích hành vi và trình bày bằng chứng để operator điều tra. Hệ thống không điều khiển máy chủ được theo dõi.

Hai miền nghiệp vụ được tách riêng:

1. **Security monitoring:** ingest log, phát hiện hành vi bất thường, phân loại IP, enrichment, alerts và điều tra.
2. **Region / Market Intelligence:** tổng hợp dữ liệu kinh tế, thương mại và địa lý để nghiên cứu cơ hội thị trường. Market context không phải security risk.

Luồng chính:

```text
Web server logs
  → WebSocket collector
  → normalize + raw archive
  → ClickHouse events + PostgreSQL state/detection
  → REST/SSE APIs
  → dashboard và IP investigation
```

## 2. Tech stack và quyền sở hữu dữ liệu

| Khu vực | Công nghệ / trách nhiệm |
|---|---|
| Backend/API | Python, FastAPI |
| Ingest transport | WebSocket client |
| Event và analytics | ClickHouse, `clickhouse-connect` |
| Mutable state | PostgreSQL, psycopg 3 |
| Realtime browser updates | SSE; PostgreSQL `LISTEN/NOTIFY` làm cross-process wake-up |
| Frontend | HTML, CSS và JavaScript; không cần SPA framework |
| Map | MapLibre GL JS |
| Statistical anomaly detection | scikit-learn Isolation Forest |
| Local geospatial aggregation | H3, OSM và GHSL urban context |
| Raw archive | local spool, Zstandard, SHA-256, Azure Blob |
| Local case explanation | llama.cpp server với Foundation-Sec GGUF và JSON Schema output |
| Scheduling | process riêng; macOS LaunchAgent được hỗ trợ |
| Tests | pytest; browser checks theo môi trường/harness |

### Quyền sở hữu dữ liệu

**ClickHouse** sở hữu raw HTTP events, event history, time-series, request/path analytics và các phép tổng hợp số lượng lớn.

**PostgreSQL** sở hữu IP profiles, classification/risk state, evidence, intelligence metadata, provider status, checkpoint/lease, idempotency, alerts/outbox, change feed, AI jobs và region/market read models.

SQLite không thuộc runtime architecture. Không có chế độ SQLite fallback hoặc offline analysis mode.

## 3. Kiến trúc và luồng dữ liệu

```text
Remote web server
      │ WebSocket: log + source offset
      ▼
Collector session ── lease / reconnect / replay
      │
      ├── Raw archive queue → spool → sealed/compressed chunk → Azure
      │
      ▼
Batch intake → normalization → bounded storage queue
      │
      ├── ClickHouse: durable immutable events
      └── PostgreSQL: detection, profile, checkpoint, change feed
                                  │
                     NOTIFY(cursor) ──→ API processes ──→ SSE
                                  │                         │
                                  └──── durable delta API ←┘
                                                            ▼
                                                        Browser UI
```

Collector commit giữ nguyên tính replay-safe: event được ghi bền vững và state/checkpoint được xử lý trước khi source offset được xác nhận. Offset chỉ tiến sau khi batch được xử lý thành công. Nếu commit lỗi, storage worker retry; queue có giới hạn để chậm lại bằng backpressure thay vì âm thầm loại raw batch.

`app/main.py` wiring các routers và khởi động component theo `APP_ROLE`. Role FastAPI được hỗ trợ là `all`, `api`, `collector`, `worker`, `ai`; data scheduler chạy riêng bằng `python -m scripts.ops.data_scheduler`.

## 4. Collector, độ bền và raw log

### WebSocket collector

Collector nhận log stream theo `source_id`, `log_key` và offset. Nó quản lý session, trạng thái, batch, retry, storage và callback hậu commit.

Kỹ thuật chính:

- **Lease ownership và fencing:** chỉ process giữ lease hợp lệ mới được ghi/commit checkpoint; lease mất thì socket đóng và batch chưa commit bị loại khỏi RAM để replay từ durable offset.
- **Reconnect với backoff:** lỗi transient đưa session vào retry, tăng delay có giới hạn; không tự bỏ qua khoảng offset.
- **Batching:** nhận nhiều log, gom theo batch/flush interval rồi đưa vào một storage queue có giới hạn.
- **Deterministic identity:** event ID được tạo ổn định từ source, offset và raw line; batch identity ổn định theo source và offset range để bảo vệ replay/idempotency.
- **Ordered commit:** storage worker xử lý tuần tự theo thứ tự nhận; không xác nhận offset trước kết quả commit.
- **Bounded queues/backpressure:** queue đầy hoặc storage chậm sẽ làm producer chờ/stream reconnect theo contract thay vì drop dữ liệu âm thầm.
- **Workload governance:** collector theo dõi áp lực queue để trì hoãn workload nền trước các đường ingest/durable storage.

Giá trị mặc định trong collector config là batch tối đa 200 dòng và flush mỗi 1.000 ms; storage queue có giới hạn 1.000 batch. Các giá trị này có thể cấu hình qua environment, không phải cam kết throughput cố định.

### Fast Detection

Fast Detection là preliminary path rẻ: kiểm tra marker high-confidence như `/.env`, `/.git`, `wp-config.php`, `phpmyadmin` và các WordPress/admin paths. Correlation dùng bounded per-IP windows, TTL, cooldown và giới hạn số IP trong memory; các ngưỡng được quản lý trong `rules/early/short-window.json`.

Early Alert có thể cảnh báo sớm nhưng không thay Stage-2 classification, score, checkpoint hay verdict cuối cùng.

### Raw log archive

Raw line được ghi song song với fast path vào `data/raw-log-spool/` theo source/ngày/giờ. Archive có bounded queue (mặc định 10.000 dòng / 64 MiB); áp lực cao được cảnh báo trước khi queue đầy. Chunk được seal theo giờ UTC hoặc khi đạt 128 MiB, lưu metadata và checksum.

Luồng archive:

```text
raw lines → spool writer → sealed chunk + sidecar
          → Zstandard compression → integrity verification
          → Azure block upload → remote checksum/manifest
          → local cleanup only after verified upload
```

Có retry, status/pressure metrics, job nền để xử lý artifact còn sót sau outage, và CLI replay để đọc lại chunk đã archive. Raw archive phục vụ recovery/forensics; raw replay không tái tạo chính xác mọi mutable analyst, alert hoặc AI state.

Source chính: `app/collectors/`, `app/services/raw_log_archive.py`, `raw_archive_compression.py`, `raw_archive_upload.py`, `scripts/ops/replay_raw_archive.py`.

## 5. Chuẩn hóa và lưu trữ

### Normalization

Apache combined access log được parse thành event có các trường chuẩn như IP, timestamp, HTTP method, path, status, bytes, referer và user agent. Raw line vẫn được giữ cho investigation. Parse rejection được ghi với source offset, raw-line hash, parser version và error code để quan sát lỗi mà không làm mất bằng chứng gốc.

Path canonicalization phục vụ phân tích traffic và rare path; không áp dụng lower-case mù quáng cho URL path. Parser/version và event identity hỗ trợ tái lập, phân biệt dữ liệu lỗi và tránh đếm trùng.

### Lưu trữ hai database

| ClickHouse | PostgreSQL |
|---|---|
| HTTP events bất biến | IP profile và current state |
| Traffic/time buckets | Detection/classification/evidence |
| Path/request analytics | Checkpoint, lease, idempotency |
| Historical queries và raw-log tail | Alerts, outbox, jobs, intelligence status |
| Behavior events và country-demand source events | Change feed, AI state, market read models |

Kết nối và query được đặt sau storage/repository modules. FastAPI routers điều phối; business policy thuộc services/core thay vì route handler.

## 6. Detection, scoring và evidence

### Các lớp phát hiện

1. **Fast Detection / Early Alert:** marker high-confidence và cửa sổ ngắn bounded trong memory; mục tiêu là độ trễ thấp.
2. **Behavior rules:** phát hiện pattern như brute force, burst, scan/sensitive-path probing, bot và tỷ lệ HTTP 4xx. Rule được lưu thành JSON, có schema và test fixtures.
3. **Rare Path:** phân tích thống kê theo lịch sử và tập IP; chạy batch/background, là supporting evidence, không tự chứng minh malicious và hiện không tự tăng score theo README contract.
4. **Isolation Forest:** học/anomaly scoring trên feature windows trong worker riêng; output được lưu như AI anomaly evidence/score, không block ingest.
5. **Threat/network context:** Tor, VPN, proxy, hosting, ASN hoặc feed match bổ sung bối cảnh; không tự kết luận một IP xấu.

### Scoring và classification

Risk được giải thích theo các nhóm đóng góp:

| Nhóm | Ý nghĩa |
|---|---|
| A — Behavior | Request pattern, probing, burst, bot, lỗi HTTP |
| B — Network identity | Tor/proxy/VPN/hosting; contribution có giới hạn |
| C — Trusted network | Context mạng/tổ chức đáng tin khi behavior thấp |
| D — Conflict context | Geo/network conflict chỉ được dùng có điều kiện |
| E — AI anomaly | Isolation Forest signal đủ điều kiện |

Classifier runtime hiện dùng các nhóm **A–E**; campaign correlation nhóm F còn được nhắc trong README cũ nhưng chưa nằm trong `classify_ip()` hiện tại. Chi tiết score đang áp dụng: A là behavior score; B cộng Tor/proxy/VPN/hosting với trần +25; C giảm 20 khi organization confidence ≥70, không hosting và behavior <25; D chỉ có thể cộng tối đa +5 khi đã có behavior; E cộng +8 khi behavior <25, anomaly score ≥70 và đã có ít nhất 3 windows. Score cuối được clamp về 0–100. Label `unknown` áp dụng khi traffic/evidence chưa đủ; hard sensitive probing hoặc base score ≥60 thành `critical`; score ≥30 hoặc AI bonus thành `medium`; score ≥10 thành `low`; còn lại là `good`. Confidence/data health được trả kèm verdict, không thay evidence.

### Evidence

Evidence là contract chung nối rule, behavior, rarity, privacy/reputation, AI anomaly và geo/network context. Evidence giữ nguồn, mã/tên detector, giá trị quan sát/threshold, thời gian, giải thích và contribution khi có.

Evidence được dùng trong IP Detail, Alerts, What Changed và CasePacket. Geo/network disagreement và confidence không bị biến thành behavior risk một cách tự động.

Source chính: `app/core/evidence.py`, `fast_detection.py`, `intelligence.py`, `traffic_validity.py`, `path_canonicalization.py`, `app/core/rules/`, `rules/behavior/`, `rules/early/`, `app/services/rare_path_detector.py`, `app/ai/detector.py`.

## 7. Threat intelligence và enrichment

Enrichment làm giàu IP bằng provider/local dataset và được thực hiện ở background, không gọi mạng đồng bộ theo từng event hay trong API request hot path.

Các loại context hiện có trong provider/service layer gồm:

- IP geolocation và ASN/network registration;
- hosting/datacenter, Cloudflare và network organization;
- Tor exit list;
- VPN/proxy/anonymous network và FireHOL/X4BNet-style lists;
- SAPICS ip-location-db, local MaxMind-compatible GeoIP và ip2region context;
- RIR delegated statistics làm registration context, không làm physical geolocation;
- provider freshness/status, local GeoIP/IP2Region datasets và conflict/confidence.

Pipeline snapshot intelligence dùng staging/COPY và set-based PostgreSQL diff. Snapshot giống hệt không update hàng loạt current rows; state chỉ được ghi khi added/changed/removed/reactivated. Safety gate từ chối snapshot rỗng hoặc shrink bất thường theo policy; nhiều bảng thuộc cùng provider được apply trong transaction để tránh trạng thái một nửa.

Geo semantics tách riêng operational location, RIR registration, candidate sources và confidence. RIR country không được diễn giải là vị trí vật lý. Nếu nguồn khác nhau, candidate/conflict được giữ lại; thiếu dữ liệu giữ `null`/unknown thay vì bịa giá trị.

Source chính: `app/providers/`, `app/core/enrichment*.py`, `app/services/geo_*.py`, `global_geo.py`, `intel_updater.py`, `pg_intel.py`, `snapshot_diff.py`, `sapics_updater.py`, `ip2region_updater.py`.

## 8. Alerts và điều tra

### Alert inbox

Alerts được lưu bền vững trong PostgreSQL, tách khỏi IP classification và không dùng Telegram outbox làm nguồn chân lý. Alert đại diện cho chuyển severity có ý nghĩa, có trạng thái `new`, `acknowledged`, `resolved`, severity columns, status/severity filters, cursor pagination, load-more và action mở IP Detail.

Kỹ thuật:

- keyset/cursor pagination có deterministic tie-breaker;
- total count tính theo filter, không bị cursor làm thay đổi;
- dedupe theo alert/evidence contract;
- outbox hỗ trợ delivery retry;
- Telegram notification là adapter tuỳ chọn và không thay PostgreSQL alert làm nguồn chân lý;
- acknowledge/resolve là analyst state;
- auto-explain Critical là tuỳ chọn, mặc định không tự chạy nếu setting không bật.

### IP Detail

IP Detail hợp nhất summary/classification, request activity, detections, evidence, network location/intelligence, privacy/reputation và nguồn dữ liệu. Các tab tổ chức cùng dữ liệu client-side; mục tiêu là không phát sinh API query không cần thiết hoặc reload toàn trang khi chỉ chuyển tab.

### Raw Log Tail

Raw Log Tail đọc những event mới nhất từ ClickHouse cho việc triage nhanh, hiển thị theo dạng bảng/dòng và cho phép mở IP Detail. Đây là màn hình quan sát log đã ingest, không phải terminal trên remote server.

Source chính: `app/routers/alerts.py`, `ai_explanations.py`, `raw_logs.py`, `ip_detail.py`, `app/db/alert_repository.py`, `state_repository.py`, templates và static JS tương ứng.

## 9. Region / Market Intelligence

Market Intelligence là sản phẩm phụ trợ nghiên cứu thương mại, **không tham gia IP security score**.

### Country / demand context

- World Bank WDI cung cấp chỉ số kinh tế vĩ mô như GDP, dân số, nhập khẩu và công nghiệp.
- UN Comtrade cung cấp trade/import context theo sản phẩm/mã HS.
- FAOSTAT, ILOSTAT và BGS bổ sung bối cảnh ngành/sản xuất/lao động/vật liệu khi có dữ liệu phù hợp.
- Vietnam sources gồm NSO PX-Web, Foreign Investment Agency/FDI material, InvestVietnam, doanhnghiep.vn registry proxy, Geofabrik/OSM, GeoBoundaries, GeoNames và GHSL.
- Product tracks hiện có context cho woodworking và metalworking; mỗi source giữ provenance/freshness và limitation riêng.
- Country demand sử dụng traffic đã quan sát như validation/context; qualified sessions, visitor identity, time windows, confidence và coverage được lưu theo snapshot.
- Opportunity score/read model được tính trong backend; browser chỉ trình bày giá trị và explanation đã được API trả về.

Trong demand calculation hiện hành, demand strength được nén theo logarithm; country demand score kết hợp strength, engagement quality và momentum với trọng số 50/30/20, rồi renormalize nếu thiếu thành phần. Confidence dựa trên engagement-evidence coverage và sample damping. Country Opportunity shrink confidence-adjusted demand về neutral 50 trước khi blend:

```text
adjusted_demand = 50 + demand_confidence × (country_demand_score − 50)
opportunity     = 0.60 × market_score + 0.40 × adjusted_demand
```

Country product prior dùng tối đa sáu tín hiệu normalized: HS imports (0.35), relevant exports (0.20), sector consumption (0.20), manufacturing growth (0.10), labor-cost pressure (0.10) và cement consumption (0.05). Missing signals được loại khỏi mẫu số thay vì biến thành zero. Market-potential v1 còn có city-fit và internal sales/RFQ validation; trọng số được điều chỉnh theo độ đầy đủ của evidence, nên không nên mô tả mọi market/city view bằng một công thức duy nhất.

Ở market-potential v1, external country prior và city fit có trọng số mặc định 60/40; khi thiếu một nguồn, nguồn còn lại được renormalize. Sales/RFQ validation lấy trọng số nội bộ tăng dần theo số RFQ (đến ngưỡng `k`) và giảm tỷ trọng external prior tương ứng. Confidence riêng phản ánh coverage, freshness, source quality và internal validation. Đây là mô hình market-potential, khác công thức Country Opportunity ở trên.

### Vietnam province/city evidence

Vietnam pipeline làm việc với geography foundation, đơn vị hành chính hiện hành, NSO indicators, FDI/industrial context, enterprise proxies và OSM/H3 observations. GeoBoundaries/GeoNames/GHSL hỗ trợ administrative/urban mapping.

OSM/enterprise registry observations được ghi là proxy/discovery evidence, không được gọi nhầm là official factory count. Missing values khác với observed zero. Project context hiện hướng tới evidence-first profile cho 34 tỉnh/thành và không công bố composite Province Potential Score nếu methodology chưa được phê duyệt.

Kỹ thuật chính:

- H3 cells để chuẩn hóa không gian và join area/city memberships;
- geometry/boundary mapping để gắn cells với geography;
- snapshot và read-model publication thay vì query nguồn ngoài theo dashboard request;
- overlap/calibration và coverage metadata để giải thích hạn chế dữ liệu;
- refresh theo batch, riêng từng source có freshness/provenance.

Source chính: `app/core/country_demand.py`, `market_potential.py`, `industrial_demand.py`, `vietnam_geography.py`, `services/province_profile.py`, `map_intelligence.py`, `services/country_demand.py`, `app/db/market_*`, `scripts/market/`, `scripts/geo/`.

## 10. API, SSE và giao diện

### REST và pages

FastAPI cung cấp health/liveness, traffic analytics, IP state/detail, alerts, raw-log tail, regions, map intelligence, behavior events và AI explain jobs. Routers chịu trách nhiệm parse request/response và gọi service/repository phù hợp.

Behavior/session tracker có JavaScript và ingestion API nhưng dashboard hiện cấu hình `enabled: false`; không nên trình bày nó như telemetry đang được thu thập trong deployment local mặc định.

### Realtime flow

```text
PostgreSQL transaction writes ip_change_log
      → trigger NOTIFY(cursor)
      → each API process LISTENs
      → process-local realtime bus wakes its SSE clients
      → browser fetches durable delta by cursor
```

PostgreSQL `NOTIFY` chỉ là wake-up hint; `ip_change_log` và cursor API mới là durable truth. Nếu notification bị mất, reconnect/replay theo cursor có thể lấy lại delta. Bus coalesce wake-ups để không broadcast hàng loạt cursor đang chờ cho cùng client. Browser dùng polling fallback có giới hạn khi SSE không hoạt động.

### Các màn hình

| Màn hình | Chức năng |
|---|---|
| Overview | Live counters, classification breakdown, top IP/path, traffic và health |
| IP Intelligence | Tìm/lọc IP theo country, ASN, class, disposition; mở investigation |
| IP Detail | Activity, detections, evidence, geo/network intel và manual AI explanation |
| Alerts | Inbox theo severity/status, pagination, acknowledge/resolve |
| Raw Log Tail | Xem event gần nhất và mở IP Detail |
| Global Map | Các lớp security evidence và market/geo context |
| Region/Market views | Country opportunity/demand và local area/city evidence |

UI dùng shared navigation/theme assets; dashboard ưu tiên delta updates, payload gọn và không rerender toàn trang khi không cần.

Source chính: `app/main.py`, `app/routers/`, `app/services/realtime_bus.py`, `realtime_listener.py`, `app/web/templates/`, `app/web/static/`.

## 11. Local AI Reasoner

```text
deterministic detections + persisted evidence
      → bounded CasePacket
      → asynchronous PostgreSQL job
      → local llama.cpp / Foundation-Sec
      → strict schema + evidence grounding validation
      → validated explanation or failed job
```

AI là **case explainer**, không phải nguồn authority cho classification/risk và không nằm trong collector ingest hot path.

- CasePacket có fingerprint và giới hạn evidence/request đại diện; inference view có token budget để chỉ gửi phần evidence được chọn.
- Job được dedupe theo `(case_id, evidence_fingerprint)` và lưu lifecycle `pending → running → completed/failed` trong PostgreSQL.
- Worker claim job bằng `FOR UPDATE SKIP LOCKED`; local inference concurrency hiện giới hạn ở một job tại một thời điểm.
- Provider gọi localhost HTTP, yêu cầu JSON Schema, kiểm tra response structure, enum/length, evidence ID có thuộc packet và grounding trước khi lưu kết quả.
- Timeout và max-token budget được cấu hình qua environment; giá trị local có thể là bounded experiment, không tự xem là production tuning đã được chứng minh.
- AI trigger tự động là chức năng riêng, có policy/dedupe/backlog controls và mặc định disabled; manual explain vẫn là luồng chính.
- Raw model output không được xem là evidence/source of truth; chỉ kết quả qua validation mới được đánh dấu completed/validated.

Source chính: `app/services/case_packets.py`, `ai_explain_worker.py`, `ai_trigger_consumer.py`, `app/ai/inference_view.py`, `reasoning.py`, `providers/llama_cpp.py`, `db/ai_jobs.py`, `scripts/ai/`.

## 12. Workers, scheduler và vận hành

### Process roles

FastAPI lifecycle bật component theo `APP_ROLE`:

| Role | Trách nhiệm chính |
|---|---|
| `all` | Local compatibility mode, chạy các runtime role trong một process |
| `api` | HTTP routes và PostgreSQL realtime listener |
| `collector` | WebSocket collector |
| `worker` | Classification watcher, coverage và enrichment queue |
| `ai` | Isolation Forest AI runtime |

Data scheduler là process riêng; không dùng `APP_ROLE=scheduler` trong Uvicorn. `scripts/dev_run.sh` hỗ trợ local services/app nhưng không phải production supervisor.

### Data refresh scheduler

`scripts/ops/data_scheduler.py` điều phối provider/market/geography/intelligence/retention jobs. Mỗi source có due-state/freshness để invocation thường xuyên không đồng nghĩa mọi dữ liệu đều tải lại mỗi lần. Process lock ngăn scheduler runs chồng lấn.

Trên macOS, `data_scheduler_launchd.py` tạo LaunchAgent. `RunAtLoad` chạy sau khi user login; `StartInterval` gọi scheduler theo chu kỳ. PostgreSQL/ClickHouse vẫn phải chạy cho các task phụ thuộc database. SAPICS và ip2region có lịch refresh riêng; lỗi download giữ last-good local dataset.

### Metrics và health

Health endpoints tổng hợp trạng thái PostgreSQL, ClickHouse, collector, parser, archive, workload và workers. Request middleware ghi request ID và duration; metrics hiện có một phần process-local nên chưa đồng nghĩa với central metrics backend/HA observability.

## 13. Backup, restore và retention

- PostgreSQL backup dùng logical dump dạng custom và upload theo backup-set/manifest.
- ClickHouse backup dùng native backup flow; artifact được upload và verify checksum.
- Raw logs được archive immutable; có thể replay để tái dựng raw events và phần detection state hỗ trợ.
- Manifest/checksum giúp phát hiện artifact thiếu hoặc hỏng; local cleanup chỉ sau successful verification.
- Restore phải được kiểm tra thực tế; backup tạo thành công chưa đủ để kết luận restore-ready.
- PostgreSQL mutable analyst/alert/AI state không được tái tạo chính xác chỉ bằng raw replay.
- Retention của current state, event data, change history và archive là các policy riêng; cleanup có giới hạn/time budget và chạy ngoài ingest hot path.
- Snapshot intelligence dùng **delta history** cho added/changed/removed/reactivated thay vì ghi lại toàn snapshot mỗi lần. Identical refresh hướng tới zero current/history writes.

Source chính: `scripts/ops/backup_*.py`, `backup_set.py`, `retention.py`, `app/services/retention_cleanup.py`, `infra/postgres/`, `infra/clickhouse/`.

## 14. Security và ranh giới sản phẩm

- Có trusted-host validation, configurable security headers, request ID và optional gzip.
- Khi bật auth, app tin identity/role headers chỉ từ trusted reverse proxy CIDR; API enforce role groups như Viewer/Analyst/Admin theo route/action.
- `/livez` là liveness surface tối giản; detailed health chịu auth khi auth bật.
- Production preflight kiểm tra cấu hình exposure như trusted hosts/proxy-auth/database settings; HTTPS/SSO thật vẫn là trách nhiệm deployment/reverse proxy.
- Input log, URL và telemetry là dữ liệu không tin cậy; frontend/API phải escape/validate trước khi trình bày hoặc xử lý.
- Không có chức năng block IP, đổi firewall, sửa cấu hình remote server, SSH, chạy lệnh hoặc remediation tự động.
- Không ghi secrets/token/cookie vào source, tài liệu, job result hoặc log.

Source chính: `app/core/authorization.py`, `proxy_auth.py`, `request_context.py`, middleware trong `app/main.py`, `scripts/ops/validate_production_config.py`.

## 15. Test và kiểm chứng

Test suite được chia theo hành vi: parser/normalization; rules/scoring/evidence; replay/checkpoint/lease; repositories/migrations; provider lifecycle; alert/API/UI; AI jobs/validation; country demand/market/geography; raw archive/backup/retention; health/security.

Các kỹ thuật test được dùng:

- unit tests cho pure policy/parser/validator;
- fake repositories/connections để test SQL contract và worker transitions;
- failure injection ở các ranh giới commit để kiểm tra rollback/fencing/replay;
- synthetic data và disposable rows cho retention/market;
- native integration marker cho PostgreSQL/ClickHouse khi service khả dụng;
- browser contract/Playwright smoke khi app và browser harness được bật;
- benchmark/soak scripts cho API read path, SSE fan-out và ingest-to-browser latency.

Unit pass không thay thế native DB integration, browser smoke, soak hay restore drill. Kết quả production readiness cần ghi rõ loại evidence và môi trường thực hiện.

Các điểm vào chính: `tests/`, `scripts/ops/realtime_read_benchmark.js`, `realtime_sse_soak.py`, `realtime_end_to_end_probe.py`, `scripts/cutover_gate.sh`.

## 16. Những điều hệ thống không làm

- Không thay đổi hay điều khiển máy chủ được theo dõi.
- Không coi một IP geolocation/provider match là bằng chứng malicious.
- Không dùng Rare Path hoặc Isolation Forest như phán quyết không giải thích.
- Không để LLM quyết định risk/classification hoặc tạo evidence mới.
- Không chuyển raw events hoặc mutable state sang database khác nếu chưa có bottleneck đo được và quyết định kiến trúc.
- Không coi backup thành công là restore đã được chứng minh.
- Không coi tính năng/config có trong source là đã được deploy/bật ở mọi môi trường.

---

## Bản đồ source nhanh

| Khu vực | Thư mục/file tiêu biểu |
|---|---|
| App wiring/config | `app/main.py`, `app/config/` |
| Collector/reliability | `app/collectors/`, `app/db/checkpoints.py` |
| Parsing/evidence/detection | `app/core/`, `app/core/rules/`, `rules/` |
| PostgreSQL/ClickHouse | `app/db/`, `infra/postgres/`, `infra/clickhouse/` |
| Network/geo providers | `app/providers/`, `app/services/geo_*`, `app/core/enrichment*` |
| Alerts/realtime | `app/routers/alerts.py`, `app/services/realtime_*`, `app/db/alert_repository.py` |
| Market/geo jobs | `scripts/market/`, `scripts/geo/`, `app/services/province_profile.py` |
| Local AI | `app/ai/`, `app/services/ai_explain_worker.py`, `scripts/ai/` |
| Dashboard | `app/web/templates/`, `app/web/static/` |
| Operations | `scripts/ops/`, `scripts/dev_run.sh` |
| Tests | `tests/` |
