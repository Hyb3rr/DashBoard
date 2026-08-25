## Mục lục
- [Tech Stack](#tech-stack)
- [Kiến trúc hệ thống](#kiến-trúc-hệ-thống)
- [Các kỹ thuật để tối ưu](#các-kỹ-thuật-để-tối-ưu)
- [1. Web Server](#1-web-server)
- [2. Log Collector](#2-log-collector)
- [3. Normalizer](#3-normalizer)
- [4. Data Storage](#4-data-storage)
  - [ClickHouse](#clickhouse)
  - [PostgreSQL](#postgresql)
- [5. Detection & Analysis](#5-detection--analysis)
  - [Behavior Detection](#behavior-detection)
  - [Threat Intelligence](#threat-intelligence)
- [6. Scoring & Context](#6-scoring--context)
- [7. Region / Market Intelligence](#7-region--market-intelligence)
- [8. FastAPI](#8-fastapi)
- [9. Realtime Dashboard](#9-realtime-dashboard)
- [Hướng phát triển](#hướng-phát-triển)
  - [Unified Evidence](#unified-evidence)
  - [Local AI Reasoner](#local-ai-reasoner)
  - [Thêm tiềm năng mua hàng ở từng thành phố](##Thêm tiềm năng mua hàng ở từng thành phố)

Demo:
[Sensitive path](https://drive.google.com/drive/folders/1DvwZV9QClBiKu6J_3zBe2Hcmjzc0Sya7?usp=sharing)

# Tech stack

| Thành phần          | Công nghệ                                  |
| ------------------- | ------------------------------------------ |
| Backend             | Python, FastAPI                            |
| Event Storage       | ClickHouse                                 |
| State Storage       | PostgreSQL                                 |
| Log Transport       | WebSocket                                  |
| Realtime UI         | Server-Sent Events                         |
| Frontend            | HTML, CSS, JavaScript                      |
| Detection           | Rules, Rare Path                           |
| Machine Learning    | Isolation Forest                           |
| Intelligence        | Geo, ASN, FireHOL, Tor, Proxy/VPN datasets |
| Market Intelligence | World Bank WDI, UN Comtrade                |


# Kiến trúc hệ thống

![[./attachments/system_structure.png]]


# Các kỹ thuật để tối ưu
## Tách biệt luồng realtime
- Luồng ingest được tách khỏi các workload nền có chi phí xử lý cao.
- Early Detection chỉ sử dụng các rule nhẹ và state ngắn hạn trong memory, trong khi Rare Path, Isolation Forest, enrichment, market refresh và OSM processing chạy ngoài Collector hot path.

## Điều phối workload khi hệ thống quá tải
Hệ thống để ưu tiên các chức năng quan trọng khi tài nguyên bị áp lực.
**Collector và ingest raw log** -> **Fast Detection và Early Alert** -> **Durable storage và checkpoint** -> **Deep/background analysis**.

## Ingest bền vững và replay an toàn
Raw event chỉ được ACK sau khi đã xử lý bền vững.
Cơ chế reconnect/replay được thiết kế idempotent để không làm tăng duplicate hoặc double-count khi kết nối bị gián đoạn rồi khôi phục.
Giúp khi kết nối lại với log vẫn tiếp tục được từ lúc bị mất kết nối

## Backpressure thay vì âm thầm làm mất dữ liệu
Các queue đều có giới hạn.
Khi storage xử lý chậm hơn tốc độ ingest, hệ thống áp dụng backpressure để xử lý đầy đủ log thay vì âm thầm drop raw log.
## Phân tách workload lưu trữ
ClickHouse chịu trách nhiệm cho event bất biến, lịch sử truy cập và các workload phân tích theo thời gian.
PostgreSQL chịu trách nhiệm cho mutable state như IP profile, evidence, classification, intelligence state, job state và các read-model hiện tại.




---
## 1. Web Server

Web Server là nguồn sinh dữ liệu cho hệ thống.
Các access/audit log ghi lại thông tin như:
- IP truy cập
- thời gian
- HTTP method
- URL/path
- HTTP status
- User-Agent
Server được giám sát chỉ có nhiệm vụ gửi log ra ngoài.

---
## 2. Log Collector

Log được truyền từ Web Server về hệ thống thông qua **WebSocket**.
Collector chịu trách nhiệm nhận log realtime và hỗ trợ reconnect/replay khi kết nối bị gián đoạn nhằm hạn chế:
- mất log;
- xử lý trùng;
- sai lệch trạng thái sau reconnect.

### Fast path và storage path

Raw access-log line được kiểm tra qua Fast Detection trước khi đi vào storage path:

```
Raw Log
   ↓
Fast Detection
   ↓
Early Alert Queue → SSE / Telegram
   ↓
Bounded Storage Queue
   ↓
ClickHouse → PostgreSQL
```


Isolation Forest draait als onafhankelijke Stage-2 periodic worker buiten de
Collector hot path. Resultaten worden opgeslagen in PostgreSQL
`ip_ai_scores` en via `ai_profile`, `/api/ips/summary` en `/health` gelezen.
IP chưa có snapshot AI hợp lệ trả `ai_status: "pending"` và profile rỗng;
API không chạy model để phục vụ request. AI không tự thay đổi BAD/WATCH.

Phase 3 validation dùng artificial slow AI để kiểm tra isolation: AI worker có
thể chậm nhưng ingest, Early Alert SSE/Telegram, storage và checkpoint vẫn phải
tiến độc lập; test không dùng sleep để che race.

Phase 4 acceptance kiểm tra advisory lock không cho AI cycle chạy chồng, AI state
đã persist có thể đọc lại, và các test replay/failure injection hiện tại vẫn giữ
raw-event idempotency, checkpoint và duplicate invariants.

Fast Detection chỉ dùng high-confidence path markers như `/.env`, `/.git`,
`wp-config.php`, `phpmyadmin` và `adminer`. Nó không chờ database, không thay đổi
classification và không sở hữu checkpoint.

Early Alert có trạng thái `preliminary`; Final Alert vẫn do PostgreSQL
`alert_outbox` làm nguồn durable. Storage queue xử lý tuần tự để giữ nguyên
checkpoint, ACK, replay và idempotency hiện tại. Queue đầy tạo backpressure để
không làm mất raw log; Early Alert queue có giới hạn riêng và chỉ báo degraded
qua metric khi overflow.

---

## 3. Normalizer
Log thô từ Web Server được parse và chuyển thành cấu trúc dữ liệu thống nhất trước khi xử lý.
Path cũng được chuẩn hóa để phục vụ các chức năng như thống kê traffic, detection và Rare Path Analysis.

---

## 4. Data Storage
Sau khi chuẩn hóa, dữ liệu được chia theo hai loại workload.
### ClickHouse
ClickHouse lưu **event và lịch sử truy cập**.

### PostgreSQL
PostgreSQL lưu **trạng thái hiện tại** của hệ thống.

---

## 5. Detection & Analysis

Dữ liệu từ ClickHouse và PostgreSQL được sử dụng bởi nhiều lớp phân tích.

###   Behavior Detection
Gồm ba cơ chế chính:
**Rules** phát hiện các pattern đã biết như request burst, brute-force, sensitive path probing hoặc nhiều HTTP 4xx.
**Rare Path** tìm các URL/path ít xuất hiện dựa trên lịch sử truy cập và số lượng IP từng truy cập path đó.
**Isolation Forest** phát hiện các hành vi bất thường về mặt thống kê mà các rule cố định có thể chưa mô tả được.

Fast Detection có thêm correlation ngắn hạn trong memory cho Early Alert:

```text
IP → bounded window → threshold → preliminary alert
```

Window có TTL; state hết hạn sẽ bị xóa. Notification có cooldown theo `(IP, rule)` để cùng một burst không tạo alert storm. Các ngưỡng dùng lại từ rule hiện tại: `WEB-BRUTE-001`, `WEB-BURST-001` và `WEB-SCAN-001`. State này chỉ tạo `preliminary` alert; không thay đổi Stage 2 score, classification, checkpoint hoặc replay.

  Threat Intelligence
IP đồng thời được enrich bằng các nguồn intelligence để xác định:
- Geo / ASN
- Hosting
- VPN
- Proxy
- Tor
- FireHOL
- Abuse-related feeds
Threat Intelligence chủ yếu cung cấp **context và supporting evidence**, không tự động kết luận một IP là malicious.

---

##  6. Scoring & Context
Các tín hiệu sau khi phân tích được tổng hợp để tạo **IP Score**.
Behavior là thành phần chính, trong khi Network Intelligence và AI đóng vai trò bổ sung ngữ cảnh.

|Nhóm|Ý nghĩa|Điểm|
|---|---|--:|
|**A – Behavior**|Hành vi request, probing, burst, bot, lỗi HTTP...|0–100|
|**B – Network Identity**|Tor, Proxy, VPN, Hosting|tối đa +25|
|**C – Trusted Network**|Mạng/tổ chức xác định rõ và hành vi thấp|-20|
|**D – Conflict Context**|Bối cảnh xung đột địa chính trị, chỉ dùng khi đã có hành vi đáng ngờ|+0 đến +5|
|**E – AI Anomaly**|Isolation Forest phát hiện anomaly đủ mạnh|+8|
|**F – Campaign Correlation**|Nhiều IP cùng ASN có hành vi/path tương đồng|+0 đến +5|
Network được tính:
```
Tor      → +15
Proxy    → +10
VPN      → +8
Hosting  → +5

Tổng nhóm B tối đa +25.
```

Kết quả cuối cùng được phân loại thành:
```
UNKNOWN
→ quá ít dữ liệu và chưa có behavior/network/AI signal

GOOD
→ chưa đạt ngưỡng đáng ngờ

WATCH
→ Score ≥ 30
  hoặc AI anomaly đủ điều kiện

BAD
→ Score nền ≥ 60
  hoặc phát hiện hard behavior như sensitive probing
```


Mỗi kết quả đi kèm **Evidence** để giải thích những tín hiệu nào đã góp phần tạo ra đánh giá đó.

Ví dụ:
```
IP
 ↓
Rules
Rare Path
Isolation Forest
Threat Intelligence
 ↓
IP Score
 ↓
Classification
 ↓
Evidence
```

---

## 7. Region / Market Intelligence

Region Score là một chức năng riêng với security scoring.
Hệ thống sử dụng dữ liệu kinh tế và thương mại để đánh giá **tiềm năng thị trường của quốc gia mà IP truy cập đến từ đó**.
Nguồn chính:
- **World Bank WDI:** quy mô kinh tế, GDP/người, nhập khẩu, dân số và mức độ phát triển công nghiệp.
- **UN Comtrade:** nhu cầu nhập khẩu máy chế biến gỗ, quy mô thị trường, tăng trưởng, độ ổn định và cơ cấu sản phẩm.

Công thức tổng quát:
```
Economic Potential
= 40% Market Capacity
+ 60% Industrial Fit

Market Score
= 40% Economic Potential
+ 60% Machine Demand
```

---

### Phase 6A.1 raw local opportunity read model

Migration `004_market_local_opportunity.sql` tạo read model cho raw local
opportunity theo country, H3, area, track và OSM snapshot. Model giữ raw score,
evidence components, coverage fields, model version và missing reason. Constraint
DB buộc `insufficient_local_evidence` không được có numeric score; chưa có
calibration, ranking, overlap hoặc UI. Worker Phase 6A.2 chưa bắt đầu.

### Phase 6A.2 raw local opportunity worker

Scheduler task `LOCAL_OPPORTUNITY_REFRESH=true` reads persisted country product
demand, active OSM cell evidence and auxiliary evidence, then writes raw local
opportunity rows. Minimum gate requires all three evidence groups; otherwise
score stays `NULL` with `insufficient_local_evidence`. Woodworking and
metal-fabrication remain separate. Model version is `phase6a-raw-v1`.

No calibration, ranking, overlap, API or UI runs in Phase 6A.2.

### Phase 6B.2 H3 area membership

`AREA_MEMBERSHIP_REFRESH=true` maps active local H3 cells to the adaptive
administrative boundary level already persisted in `market_areas`, using H3
centroids and point-in-polygon. Unsupported deeper boundaries remain unmapped;
the worker never invents dangling area IDs, city radii or industrial clusters.
The worker only updates `area_id`; it does not change raw scores or calibration.
Membership version is `phase6b2-membership-v4`; IDs use existing country-code
area identity.

### Phase 6B.3 calibration distribution study v2

`local_calibration_study` chỉ đọc raw local scores và báo cáo distribution
theo `track:area_type`: count, median, IQR, p5, p25, p75, p95, skew, range,
lower/upper fence và low/high outlier counts, percentage.
Nó so sánh percentile, robust quantile và robust z-score như candidate methods,
nhưng không chọn method, không ghi calibrated score và không thay đổi dữ liệu
production. Study version hiện tại là `phase6b-study-v2`; calibration persistence
chỉ được thiết kế sau khi study PASS.

### Phase 6B.4-A calibration persistence foundation

Bootstrap migration `005_market_local_calibration.sql` adds nullable
`calibrated_score`, `peer_percentile`, `calibration_method` and
`calibration_version`, plus `calibration_status` defaulting to `not_selected`.
This phase does not select a method or write calibrated values. The canonical
`app.tools.init_storage` bootstrap applies and safely replays migration 005.

### Phase 6B.4-B calibration selection

`local_calibration` compares Percentile and Robust-Z independently per track
using deterministic peer subsamples. It reports rank correlation, median/p95
score shift and top/bottom decile retention, then persists the selected method
without changing `raw_local_score`. Cells without administrative membership are
excluded and retain NULL calibration fields.

### Phase 7A overlap / whitespace foundation

Migration `006_market_overlap.sql` adds the directional overlap read model.
It stores shared opportunity, both directional overlap ratios and remaining
opportunity for an area pair. Phase 7A defines schema and repository only;
Phase 7B will compute bounded pairs that share relevant H3 cells. No global
N² comparison, request-time computation or UI/API exposure is included.

ADM2 geography now retains its ADM1 parent identity in `market_areas`, so
overlap can compare valid hierarchy memberships without inventing territory
overlap.
Administrative source identities are namespaced by level to avoid ADM1/ADM2
identifier collisions while keeping stable area IDs.

### Phase 7B overlap computation

`LOCAL_OVERLAP_REFRESH=true` runs the scheduler-owned worker. It expands each
calibrated cell through its persisted area parents, creates only pairs sharing
an H3 opportunity cell, and stores directional overlap plus remaining
opportunity. It uses active snapshots and selected calibration rows only;
raw/calibrated scores are never overwritten. Recalculation replaces one
snapshot/track scope atomically and is idempotent. No UI/API is included.

### Phase 8A market read API

`/api/regions/{country_code}` exposes precomputed `local_opportunities` and
`overlap` rows from PostgreSQL. Requests only read persisted state; they never
run calibration, H3 or overlap computation. Empty overlap is represented as
`overlap_status=unavailable` with `insufficient_local_hierarchy`, never as a
fake 0% score.

### Phase 8B Priority V1 UI

The region detail page renders the persisted market read model under
`Local Opportunities`, split into Woodworking and Metal Fabrication. It shows
precomputed calibrated score, peer percentile, evidence status and missing
reasons. The page also shows directional Overlap / Remaining Opportunity.
The browser only formats API data; it does not run calibration, H3, overlap or
AI work. Missing local evidence remains `Not scored`, and missing hierarchy is
shown as unavailable rather than as a fake `0%` overlap.

##  8. FastAPI

FastAPI là lớp trung gian giữa backend và giao diện.
Hệ thống sử dụng:
```
REST API
→ lấy traffic, IP profile, evidence, region data...

SSE
→ đẩy những thay đổi realtime lên Dashboard
```
Nhờ SSE, giao diện có thể nhận trạng thái mới mà không cần reload toàn bộ trang.

---

##  9. Realtime Dashboard

Dashboard là nơi tổng hợp kết quả cuối cùng cho người sử dụng.
Các chức năng chính gồm:

- Traffic Overview
- IP Intelligence
- IP Score & Classification
- IP Detail
- Detection Evidence
- Rare Path Evidence
- Threat Intelligence
- Region / Market Score
- Region Detail
- Data Freshness
- What Changed
- Collector Health

# Hướng phát triển

## Thêm tiềm năng mua hàng ở từng thành phố
Tải thêm database từ các nguồn khác nhau và tính điểm để ra được khả năng mua hàng của từng khu vực

##  Unified Evidence

Chuẩn hóa output của Rules, Rare Path, Isolation Forest và Threat Intelligence thành một Evidence Model chung để việc giải thích và điều tra nhất quán hơn.

##  Local AI Reasoner

Bổ sung Local LLM ở phía sau detection pipeline:

```
Detection
    ↓
Structured Evidence
    ↓
Local AI
    ↓
Explanation / Incident Summary
```

AI sẽ hỗ trợ giải thích và tổng hợp sự cố nhưng không nằm trong ingest hot path, không tự động thay đổi classification và không điều khiển Web Server.
