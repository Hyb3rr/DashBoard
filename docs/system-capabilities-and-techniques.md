# Sentinel Hub — Chức năng và kỹ thuật

> Tài liệu này tổng hợp chức năng, data flow và kỹ thuật đang được triển khai trong repository. Bố cục bám theo [README](../README.md), nhưng mô tả chi tiết hơn và chỉ rõ khu vực source liên quan. Khi tài liệu và runtime khác nhau, code/config hiện hành là nguồn chuẩn.

## Mục lục

-   [1\. Tổng quan](#1-t%E1%BB%95ng-quan)
-   [2\. Tech stack và quyền sở hữu dữ liệu](#2-tech-stack-v%C3%A0-quy%E1%BB%81n-s%E1%BB%9F-h%E1%BB%AFu-d%E1%BB%AF-li%E1%BB%87u)
-   [3\. Kiến trúc và luồng dữ liệu](#3-ki%E1%BA%BFn-tr%C3%BAc-v%C3%A0-lu%E1%BB%93ng-d%E1%BB%AF-li%E1%BB%87u)
-   [4\. Collector, độ bền và raw log](#4-collector-%C4%91%E1%BB%99-b%E1%BB%81n-v%C3%A0-raw-log)
-   [5\. Chuẩn hóa và lưu trữ](#5-chu%E1%BA%A9n-h%C3%B3a-v%C3%A0-l%C6%B0u-tr%E1%BB%AF)
-   [6\. Detection, scoring và evidence](#6-detection-scoring-v%C3%A0-evidence)
-   [7\. Threat intelligence và enrichment](#7-threat-intelligence-v%C3%A0-enrichment)
-   [8\. Alerts và điều tra](#8-alerts-v%C3%A0-%C4%91i%E1%BB%81u-tra)
-   [9\. Region / Market Intelligence](#9-region--market-intelligence)
-   [10\. API, SSE và giao diện](#10-api-sse-v%C3%A0-giao-di%E1%BB%87n)
-   [11\. Local AI Reasoner](#11-local-ai-reasoner)
-   [12\. Workers, scheduler và vận hành](#12-workers-scheduler-v%C3%A0-v%E1%BA%ADn-h%C3%A0nh)
-   [13\. Backup, restore và retention](#13-backup-restore-v%C3%A0-retention)
-   [14\. Security và ranh giới sản phẩm](#14-security-v%C3%A0-ranh-gi%E1%BB%9Bi-s%E1%BA%A3n-ph%E1%BA%A9m)
-   [15\. Test và kiểm chứng](#15-test-v%C3%A0-ki%E1%BB%83m-ch%E1%BB%A9ng)

## 1\. Tổng quan

Sentinel Hub là hệ thống **giám sát web server theo hướng read-only**. Máy chủ được theo dõi chỉ gửi log

Sentinel Hub nhận telemetry, phân tích hành vi và trình bày bằng chứng để operator điều tra. Hệ thống không điều khiển máy chủ được theo dõi.

Hai miền nghiệp vụ được tách riêng:

1.  **Security monitoring:** ingest log, phát hiện hành vi bất thường, phân loại IP, enrichment, alerts và điều tra.
2.  **Region / Market Intelligence:** tổng hợp dữ liệu kinh tế, thương mại và địa lý để nghiên cứu cơ hội thị trường. Market context không phải security risk.

Luồng chính:

```text
Web server logs
  → WebSocket collector
  → normalize + raw archive
  → ClickHouse events + PostgreSQL state/detection
  → REST/SSE APIs
  → dashboard và IP investigation
```

## 2\. Tech stack và quyền sở hữu dữ liệu

| Khu vực | Công nghệ / trách nhiệm |
| --- | --- |
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

Quyền sở hữu dữ liệu

**ClickHouse** sở hữu raw HTTP events, event history, time-series, request/path analytics và các phép tổng hợp số lượng lớn.

**PostgreSQL** sở hữu IP profiles, classification/risk state, evidence, intelligence metadata, provider status, checkpoint/lease, idempotency, alerts/outbox, change feed, AI jobs và region/market read models.

SQLite không thuộc runtime architecture. Không có chế độ SQLite fallback hoặc offline analysis mode.

## 3\. Kiến trúc và luồng dữ liệu

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

## 4\. Collector, độ bền và raw log

### WebSocket collector

Kỹ thuật chính:

-   **Batching:** nhận nhiều log, gom theo batch/flush interval rồi đưa vào một storage queue có giới hạn.
-   **Deterministic identity:** event ID được tạo ổn định từ source, offset và raw line; batch identity ổn định theo source và offset range để bảo vệ replay/idempotency.
-   **Workload governance:** collector theo dõi áp lực hàng chờ để trì hoãn công việc nền như enrichment, ...

Giá trị mặc định trong collector config là batch tối đa 200 dòng và flush mỗi 1.000 ms; storage queue có giới hạn 1.000 batch. Các giá trị này có thể cấu hình qua environment, không phải cam kết throughput cố định.

### Fast Detection

Kiểm tra các dấu hiệu nhận biết cao như `/.env`, `/.git` và các WordPress hoặc admin paths.

Early Alert có thể cảnh báo sớm nhưng không thay Stage-2 classification, score, checkpoint hay verdict cuối cùng.

### Raw log archive

Archive có bounded queue (mặc định 10.000 dòng / 64 MiB); áp lực cao được cảnh báo trước khi queue đầy. Chunk được seal theo giờ UTC hoặc khi đạt 128 MiB, lưu metadata và checksum.

## 5\. Chuẩn hóa và lưu trữ

### Normalization

Apache combined access log được parse thành event có các trường chuẩn như IP, timestamp, HTTP method, path, status, bytes, referer và user agent. Raw line vẫn được giữ cho investigation. Parse rejection được ghi với source offset, raw-line hash, parser version và error code để quan sát lỗi mà không làm mất bằng chứng gốc.

Path canonicalization phục vụ phân tích traffic và rare path; không áp dụng lower-case mù quáng cho URL path. Parser/version và event identity hỗ trợ tái lập, phân biệt dữ liệu lỗi và tránh đếm trùng.

### Lưu trữ hai database

| ClickHouse | PostgreSQL |
| --- | --- |
| HTTP events bất biến | IP profile và current state |
| Traffic/time buckets | Detection/classification/evidence |
| Path/request analytics | Checkpoint, lease, idempotency |
| Historical queries và raw-log tail | Alerts, outbox, jobs, intelligence status |
| Behavior events và country-demand source events | Change feed, AI state, market read models |

Kết nối và query được đặt sau storage repository modules. FastAPI routers điều phối; business policy thuộc services/core thay vì route handler.

## 6\. Detection, scoring và evidence

### Các lớp phát hiện

1.  **Fast Detection :** marker high-confidence và cửa sổ ngắn bounded trong memory; mục tiêu là độ trễ thấp.
2.  **Behavior rules:** phát hiện pattern như brute force, burst, scan, sensitive-path probing, bot và tỷ lệ HTTP 4xx. Rule được lưu thành JSON, có schema và test fixtures.
3.  **Rare Path:** phân tích thống kê theo lịch sử và tập IP; chạy batch/background, là supporting evidence, không tự chứng minh malicious và hiện không tự tăng score theo README contract.
4.  **Isolation Forest:** học anomaly scoring trên feature windows trong worker riêng; output được lưu như AI anomaly evidence score, không block ingest.
5.  **Threat/network context:** Tor, VPN, proxy, hosting, ASN hoặc feed match bổ sung bối cảnh; không tự kết luận một IP xấu.

### Scoring và classification

Risk được giải thích theo các nhóm đóng góp:

| Nhóm | Ý nghĩa |
| --- | --- |
| A — Behavior | Request pattern, probing, burst, bot, lỗi HTTP |
| B — Network identity | Tor/proxy/VPN/hosting; contribution có giới hạn |
| C — Trusted network | Context mạng hoặc tổ chức đáng tin khi behavior thấp |
| D — Conflict context | Geo/network conflict chỉ được dùng có điều kiện |
| E — AI anomaly | Isolation Forest signal đủ điều kiện |

Chi tiết score đang áp dụng:

- A là behavior score

- B cộng Tor/proxy/VPN/hosting tối đa +25

- C giảm 20 khi organization confidence ≥70 không hosting và behavior <25

- D chỉ có thể cộng tối đa +5 khi đã có behavior

- E cộng +8 khi behavior <25, anomaly score ≥70 và đã có ít nhất 3 windows

Score cuối được clamp về 0–100. Label `unknown` áp dụng khi traffic/evidence chưa đủ; hard sensitive probing hoặc base score ≥60 thành `critical`; score ≥30 hoặc AI bonus thành `medium`; score ≥10 thành `low`; còn lại là `good`. Confidence/data health được trả kèm verdict, không thay evidence.

### Evidence

Evidence là contract chung nối rule, behavior, rarity, privacy/reputation, AI anomaly và geo/network context. Evidence giữ nguồn, mã/tên detector, giá trị quan sát/threshold, thời gian, giải thích và contribution khi có.

Evidence được dùng trong IP Detail, Alerts, What Changed và CasePacket. Geo/network disagreement và confidence không bị biến thành behavior risk một cách tự động.

## 7\. Threat intelligence và enrichment

Enrichment làm giàu IP bằng provider/local dataset và được thực hiện ở background, không gọi mạng đồng bộ theo từng event hay trong API request hot path.

Các loại context hiện có trong provider/service layer gồm:

-   IP geolocation và ASN/network registration;
-   hosting/datacenter, Cloudflare và network organization;
-   Tor exit list;
-   VPN/proxy/anonymous network và FireHOL/X4BNet-style lists;
-   SAPICS ip-location-db, local MaxMind-compatible GeoIP và ip2region context;
-   RIR delegated statistics làm registration context, không làm physical geolocation;
-   provider freshness/status, local GeoIP/IP2Region datasets và conflict/confidence.

Pipeline snapshot intelligence dùng staging/COPY và set-based PostgreSQL diff. Snapshot giống hệt không update hàng loạt current rows; state chỉ được ghi khi added/changed/removed/reactivated. Safety gate từ chối snapshot rỗng hoặc shrink bất thường theo policy; nhiều bảng thuộc cùng provider được apply trong transaction để tránh trạng thái một nửa.

Geo semantics tách riêng operational location, RIR registration, candidate sources và confidence. RIR country không được diễn giải là vị trí vật lý. Nếu nguồn khác nhau, candidate/conflict được giữ lại; thiếu dữ liệu giữ `null`/unknown thay vì bịa giá trị.

## 8\. Alerts và điều tra

### Alert inbox

Alerts được lưu bền vững trong PostgreSQL, tách khỏi IP classification.
Auto-explain Critical là tuỳ chọn, mặc định không tự chạy nếu setting không bật.

### Disposition automation

Disposition là trạng thái triage của case, tách biệt với classification (đánh giá rủi ro hiện tại) và alert (sự kiện cần chú ý). Analyst có thể tự đặt trạng thái và ghi người phụ trách/ghi chú; policy tự động chỉ thực hiện các chuyển trạng thái sau:

| Trạng thái hiện tại | Điều kiện | Trạng thái mới | Lý do lưu trong history |
| --- | --- | --- | --- |
| `NEW` | Classification chuyển thành `Medium` | `MONITOR` | `medium_classification` |
| `NEW` | Classification chuyển thành `Critical` | `INVESTIGATE` | `critical_classification` |
| `MONITOR` | Classification lên `Critical` và alert chuyển severity được tạo | `INVESTIGATE` | `critical_classification` |
| `MONITOR` | Medium tái diễn với evidence fingerprint mới, ngoài cooldown 30 phút và alert recurrence được tạo | `INVESTIGATE` | `monitored_recurrence` |
| `MONITOR` | Classification trở lại `Medium` từ mức thấp hơn và alert chuyển classification được tạo | `INVESTIGATE` | `medium_classification` |

Evidence trùng, activity còn trong cooldown, hoặc không tạo được alert recurrence thì không tự chuyển `MONITOR` sang `INVESTIGATE`. Policy không tự thay đổi `INVESTIGATE`, `ESCALATE` hay `RESOLVED`; `ESCALATE` thuộc analyst, và tự mở lại case `RESOLVED` chưa nằm trong phạm vi hiện tại. Mỗi chuyển trạng thái tự động được ghi history với actor `system`, trạng thái trước/sau, thời điểm và lý do. Alert, classification và disposition được lưu cùng transaction hiện có để tránh trạng thái lệch nhau.

### IP Detail

IP Detail hợp nhất summary/classification, request activity, detections, evidence, network location/intelligence, privacy/reputation và nguồn dữ liệu. Các tab tổ chức cùng dữ liệu client-side; mục tiêu là không phát sinh API query không cần thiết hoặc reload toàn trang khi chỉ chuyển tab.

### Raw Log Tail

Raw Log Tail đọc những event mới nhất từ ClickHouse cho việc triage nhanh, hiển thị theo dạng bảng/dòng và cho phép mở IP Detail. Đây là màn hình quan sát log đã ingest, không phải terminal trên remote server.

## 9\. Region / Market Intelligence

Market Intelligence là sản phẩm phụ trợ nghiên cứu thương mại, **không tham gia IP security score**.

### Country / demand context

-   World Bank WDI cung cấp chỉ số kinh tế vĩ mô như GDP, dân số, nhập khẩu và công nghiệp.
-   UN Comtrade cung cấp trade/import context theo sản phẩm/mã HS.
-   FAOSTAT, ILOSTAT và BGS bổ sung bối cảnh ngành/sản xuất/lao động/vật liệu khi có dữ liệu phù hợp.
-   Vietnam sources gồm NSO PX-Web, Foreign Investment Agency/FDI material, InvestVietnam, [doanhnghiep.vn](http://doanhnghiep.vn) registry proxy, Geofabrik/OSM, GeoBoundaries, GeoNames và GHSL.
-   Product tracks hiện có context cho woodworking và metalworking; mỗi source giữ provenance/freshness và limitation riêng.
-   Country demand sử dụng traffic đã quan sát như validation/context; qualified sessions, visitor identity, time windows, confidence và coverage được lưu theo snapshot.
-   Opportunity score/read model được tính trong backend; browser chỉ trình bày giá trị và explanation đã được API trả về.

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

-   H3 cells để chuẩn hóa không gian và join area/city memberships;
-   geometry/boundary mapping để gắn cells với geography;
-   snapshot và read-model publication thay vì query nguồn ngoài theo dashboard request;
-   overlap/calibration và coverage metadata để giải thích hạn chế dữ liệu;
-   refresh theo batch, riêng từng source có freshness/provenance.


## 10\. API, SSE và giao diện

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
| --- | --- |
| Overview | Live counters, classification breakdown, top IP/path, traffic và health |
| IP Intelligence | Tìm/lọc IP theo country, ASN, class, disposition; mở investigation |
| IP Detail | Activity, detections, evidence, geo/network intel và manual AI explanation |
| Alerts | Inbox theo severity/status, pagination, acknowledge/resolve |
| Raw Log Tail | Xem event gần nhất và mở IP Detail |
| Global Map | Các lớp security evidence và market/geo context |
| Region/Market views | Country opportunity/demand và local area/city evidence |

UI dùng shared navigation/theme assets; dashboard ưu tiên delta updates, payload gọn và không rerender toàn trang khi không cần.

## 11\. Local AI Reasoner

```text
deterministic detections + persisted evidence
      → bounded CasePacket
      → asynchronous PostgreSQL job
      → local llama.cpp / Foundation-Sec
      → strict schema + evidence grounding validation
      → validated explanation or failed job
```

AI là **case explainer**, không phải nguồn authority cho classification/risk và không nằm trong collector ingest hot path.

-   CasePacket có fingerprint và giới hạn evidence/request đại diện; inference view có token budget để chỉ gửi phần evidence được chọn.
-   Job được dedupe theo `(case_id, evidence_fingerprint)` và lưu lifecycle `pending → running → completed/failed` trong PostgreSQL.
-   Worker claim job bằng `FOR UPDATE SKIP LOCKED`; local inference concurrency hiện giới hạn ở một job tại một thời điểm.
-   Provider gọi localhost HTTP, yêu cầu JSON Schema, kiểm tra response structure, enum/length, evidence ID có thuộc packet và grounding trước khi lưu kết quả.
-   Timeout và max-token budget được cấu hình qua environment; giá trị local có thể là bounded experiment, không tự xem là production tuning đã được chứng minh.
-   AI trigger tự động là chức năng riêng, có policy/dedupe/backlog controls và mặc định disabled; manual explain vẫn là luồng chính.
-   Raw model output không được xem là evidence/source of truth; chỉ kết quả qua validation mới được đánh dấu completed/validated.


## 12\. Workers, scheduler và vận hành

### Process roles

FastAPI lifecycle bật component theo `APP_ROLE`:

| Role | Trách nhiệm chính |
| --- | --- |
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

## 13\. Backup, restore và retention

-   PostgreSQL backup dùng logical dump dạng custom và upload theo backup-set/manifest.
-   ClickHouse backup dùng native backup flow; artifact được upload và verify checksum.
-   Raw logs được archive immutable; có thể replay để tái dựng raw events và phần detection state hỗ trợ.
-   Manifest/checksum giúp phát hiện artifact thiếu hoặc hỏng; local cleanup chỉ sau successful verification.
-   Restore phải được kiểm tra thực tế; backup tạo thành công chưa đủ để kết luận restore-ready.
-   PostgreSQL mutable analyst/alert/AI state không được tái tạo chính xác chỉ bằng raw replay.
-   Retention của current state, event data, change history và archive là các policy riêng; cleanup có giới hạn/time budget và chạy ngoài ingest hot path.
-   Snapshot intelligence dùng **delta history** cho added/changed/removed/reactivated thay vì ghi lại toàn snapshot mỗi lần. Identical refresh hướng tới zero current/history writes.

## 14\. Security và ranh giới sản phẩm

-   Có trusted-host validation, configurable security headers, request ID và optional gzip.
-   Khi bật auth, app tin identity/role headers chỉ từ trusted reverse proxy CIDR; API enforce role groups như Viewer/Analyst/Admin theo route/action.
-   `/livez` là liveness surface tối giản; detailed health chịu auth khi auth bật.
-   Production preflight kiểm tra cấu hình exposure như trusted hosts/proxy-auth/database settings; HTTPS/SSO thật vẫn là trách nhiệm deployment/reverse proxy.
-   Input log, URL và telemetry là dữ liệu không tin cậy; frontend/API phải escape/validate trước khi trình bày hoặc xử lý.
-   Không có chức năng block IP, đổi firewall, sửa cấu hình remote server, SSH, chạy lệnh hoặc remediation tự động.
-   Không ghi secrets/token/cookie vào source, tài liệu, job result hoặc log.

## 15\. Test và kiểm chứng

Test suite được chia theo hành vi: parser/normalization; rules/scoring/evidence; replay/checkpoint/lease; repositories/migrations; provider lifecycle; alert/API/UI; AI jobs/validation; country demand/market/geography; raw archive/backup/retention; health/security.

Các kỹ thuật test được dùng:

-   unit tests cho pure policy/parser/validator;
-   fake repositories/connections để test SQL contract và worker transitions;
-   failure injection ở các ranh giới commit để kiểm tra rollback/fencing/replay;
-   synthetic data và disposable rows cho retention/market;
-   native integration marker cho PostgreSQL/ClickHouse khi service khả dụng;
-   browser contract/Playwright smoke khi app và browser harness được bật;
-   benchmark/soak scripts cho API read path, SSE fan-out và ingest-to-browser latency.

Unit pass không thay thế native DB integration, browser smoke, soak hay restore drill. Kết quả production readiness cần ghi rõ loại evidence và môi trường thực hiện.

