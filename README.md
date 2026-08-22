## Mục lục
- [Tech Stack](#tech-stack)
- [Kiến trúc hệ thống](#kiến-trúc-hệ-thống)
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
# Tech stack

|Thành phần|Công nghệ|
|---|---|
|Backend|Python, FastAPI|
|Event Storage|ClickHouse|
|State Storage|PostgreSQL|
|Log Transport|WebSocket|
|Realtime UI|Server-Sent Events|
|Frontend|HTML, CSS, JavaScript|
|Detection|Rules, Rare Path|
|Machine Learning|Isolation Forest|
|Intelligence|Geo, ASN, FireHOL, Tor, Proxy/VPN datasets|
|Market Intelligence|World Bank WDI, UN Comtrade|

# Kiến trúc hệ thống

![[system_structure.png]]

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

 5. Detection & Analysis

Dữ liệu từ ClickHouse và PostgreSQL được sử dụng bởi nhiều lớp phân tích.

###   Behavior Detection
Gồm ba cơ chế chính:
**Rules** phát hiện các pattern đã biết như request burst, brute-force, sensitive path probing hoặc nhiều HTTP 4xx.
**Rare Path** tìm các URL/path ít xuất hiện dựa trên lịch sử truy cập và số lượng IP từng truy cập path đó.
**Isolation Forest** phát hiện các hành vi bất thường về mặt thống kê mà các rule cố định có thể chưa mô tả được.

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