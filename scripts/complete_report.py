from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile
import os
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "Group7_FinalReport.docx"
TMP = ROOT / "Group7_FinalReport.completed.docx"
W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
NS = {"w": W}
ET.register_namespace("w", W)


def tag(name: str) -> str:
    return f"{{{W}}}{name}"


def run(text: str, *, bold=False, italic=False, size=24, color=None):
    r = ET.Element(tag("r"))
    rp = ET.SubElement(r, tag("rPr"))
    if bold:
        ET.SubElement(rp, tag("b"))
    if italic:
        ET.SubElement(rp, tag("i"))
    ET.SubElement(rp, tag("sz"), {tag("val"): str(size)})
    ET.SubElement(rp, tag("szCs"), {tag("val"): str(size)})
    if color:
        ET.SubElement(rp, tag("color"), {tag("val"): color})
    t = ET.SubElement(r, tag("t"))
    if text[:1].isspace() or text[-1:].isspace():
        t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
    t.text = text
    return r


def paragraph(text="", *, style=None, bold=False, italic=False, size=24,
              align=None, before=0, after=100, page_break=False, color=None):
    p = ET.Element(tag("p"))
    pp = ET.SubElement(p, tag("pPr"))
    if style:
        ET.SubElement(pp, tag("pStyle"), {tag("val"): style})
    ET.SubElement(pp, tag("spacing"), {tag("before"): str(before), tag("after"): str(after), tag("line"): "276", tag("lineRule"): "auto"})
    if align:
        ET.SubElement(pp, tag("jc"), {tag("val"): align})
    if page_break:
        ET.SubElement(pp, tag("pageBreakBefore"))
    if text:
        p.append(run(text, bold=bold, italic=italic, size=size, color=color))
    return p


def bullet(text: str):
    p = paragraph(style="List Bullet", after=60)
    p.append(run(text, size=23))
    return p


def table(rows, widths=None):
    t = ET.Element(tag("tbl"))
    pr = ET.SubElement(t, tag("tblPr"))
    ET.SubElement(pr, tag("tblStyle"), {tag("val"): "Table Grid"})
    ET.SubElement(pr, tag("tblW"), {tag("w"): "0", tag("type"): "auto"})
    for ridx, row_data in enumerate(rows):
        tr = ET.SubElement(t, tag("tr"))
        if ridx == 0:
            ET.SubElement(tr, tag("trPr")).append(ET.Element(tag("tblHeader")))
        for cidx, value in enumerate(row_data):
            tc = ET.SubElement(tr, tag("tc"))
            tcp = ET.SubElement(tc, tag("tcPr"))
            if widths:
                ET.SubElement(tcp, tag("tcW"), {tag("w"): str(widths[cidx]), tag("type"): "dxa"})
            p = paragraph(after=0)
            p.append(run(str(value), bold=(ridx == 0), size=20 if ridx else 19))
            tc.append(p)
    return t


def page_break():
    p = paragraph()
    r = ET.SubElement(p, tag("r"))
    ET.SubElement(r, tag("br"), {tag("type"): "page"})
    return p


def build_body(old_body):
    sect_pr = old_body.find(tag("sectPr"))
    body = ET.Element(tag("body"))

    # Cover page: retain the university/report identity while correcting the topic.
    body.extend([
        paragraph("ĐẠI HỌC QUỐC GIA THÀNH PHỐ HỒ CHÍ MINH", bold=True, size=28, align="center", after=80),
        paragraph("TRƯỜNG ĐẠI HỌC CÔNG NGHỆ THÔNG TIN", bold=True, size=27, align="center", after=180),
        paragraph("---------------a & b---------------", size=22, align="center", after=1000),
        paragraph("BÁO CÁO THỰC TẬP", bold=True, size=34, align="center", after=180),
        paragraph("IP INTELLIGENCE – HỆ THỐNG GIÁM SÁT VÀ PHÂN TÍCH TRAFFIC WEB", bold=True, size=25, align="center", after=500),
        paragraph("Nhóm 7", bold=True, size=26, align="center", after=100),
        paragraph("Nguyễn Bá Quân", size=24, align="center", after=1000),
        paragraph("TP. Hồ Chí Minh, tháng 8 năm 2026", italic=True, size=23, align="center", after=0),
        page_break(),
        paragraph("MỤC LỤC", style="Heading1", align="center", after=180),
        paragraph("1. Tổng quan và mục tiêu", after=70),
        paragraph("2. Phân tích yêu cầu và kiến trúc hệ thống", after=70),
        paragraph("3. Công nghệ và thiết kế dữ liệu", after=70),
        paragraph("4. Quy trình xử lý dữ liệu realtime", after=70),
        paragraph("5. Phát hiện hành vi và threat intelligence", after=70),
        paragraph("6. Chấm điểm IP và phân loại rủi ro", after=70),
        paragraph("7. Region / Market Intelligence", after=70),
        paragraph("8. API, dashboard và vận hành", after=70),
        paragraph("9. Kiểm thử và đánh giá", after=70),
        paragraph("10. Kết quả, hạn chế và hướng phát triển", after=70),
        paragraph("Tài liệu tham khảo", after=70),
        page_break(),
        paragraph("DANH MỤC HÌNH ẢNH", style="Heading1", align="center", after=180),
        paragraph("Hình 1. Kiến trúc xử lý tổng thể của hệ thống", after=70),
        paragraph("Hình 2. Luồng Fast Detection và Early Alert", after=70),
        paragraph("Hình 3. Quan hệ giữa event storage và state storage", after=70),
        paragraph("Hình 4. Luồng chấm điểm và phân loại IP", after=70),
        page_break(),
        paragraph("DANH MỤC BẢNG", style="Heading1", align="center", after=180),
        paragraph("Bảng 1. Tech stack của hệ thống", after=70),
        paragraph("Bảng 2. Các lớp phát hiện và tín hiệu đầu vào", after=70),
        paragraph("Bảng 3. Ma trận điểm và phân loại", after=70),
        paragraph("Bảng 4. Kết quả kiểm thử tự động", after=70),
    ])

    def h1(text): body.append(paragraph(text, style="Heading1", bold=True, size=28, before=240, after=120, page_break=True))
    def h2(text): body.append(paragraph(text, style="Heading2", bold=True, size=25, before=160, after=90))
    def p(text): body.append(paragraph(text, size=23, after=100))
    def b(text): body.append(bullet(text))

    h1("1. Tổng quan và mục tiêu")
    p("Trong các hệ thống web hiện đại, access log là nguồn dữ liệu quan trọng để quan sát hoạt động người dùng, phát hiện hành vi tự động hóa và nhận diện dấu hiệu tấn công. Tuy nhiên, log thường có tốc độ lớn, dữ liệu không đồng nhất và cần được xử lý gần thời gian thực. Đề tài IP Intelligence xây dựng một nền tảng thu thập, chuẩn hóa, lưu trữ và phân tích traffic web nhằm biến các dòng access log thành thông tin có thể hành động.")
    p("Mục tiêu của hệ thống là cung cấp một pipeline bền vững từ Web Server đến dashboard: nhận log qua WebSocket, phát hiện sớm các mẫu nguy hiểm, lưu event để replay/phân tích lịch sử, enrich IP bằng dữ liệu địa lý và network intelligence, sau đó tính điểm rủi ro và hiển thị kết quả qua FastAPI và giao diện realtime.")
    h2("Phạm vi thực hiện")
    for x in ["Thu thập access log realtime và hỗ trợ reconnect/replay.", "Phát hiện sensitive path, brute-force, request burst, path scan, bot và các mẫu HTTP bất thường.", "Lưu event bất biến trong ClickHouse; lưu trạng thái và read-model trong PostgreSQL.", "Enrich IP với Geo/ASN, hosting, VPN, proxy, Tor, FireHOL và abuse-related evidence.", "Bổ sung Isolation Forest cho anomaly detection và dữ liệu World Bank WDI/UN Comtrade cho market intelligence."]:
        b(x)

    h1("2. Phân tích yêu cầu và kiến trúc hệ thống")
    p("Hệ thống được tổ chức theo các lớp có trách nhiệm riêng: Web Server tạo log; WebSocket Collector nhận và kiểm soát luồng dữ liệu; Normalizer chuyển log thô thành event thống nhất; Detection và Enrichment tạo tín hiệu; Storage lưu event/state; cuối cùng FastAPI và dashboard cung cấp giao diện truy vấn, theo dõi và cảnh báo.")
    body.append(table([
        ["Thành phần", "Công nghệ / vai trò"],
        ["Backend", "Python, FastAPI, asyncio"],
        ["Log transport", "WebSocket, reconnect và replay"],
        ["Event storage", "ClickHouse cho HTTP events và lịch sử"],
        ["State storage", "PostgreSQL cho profile, evidence, checkpoint, job state"],
        ["Frontend", "HTML, CSS, JavaScript; SSE cho realtime"],
        ["Detection / AI", "Rules, Rare Path, Isolation Forest"],
        ["Intelligence", "Geo, ASN, FireHOL, Tor, Proxy/VPN, WDI, UN Comtrade"],
    ], [2600, 6500]))
    h2("Nguyên tắc tối ưu")
    for x in ["Tách hot path ingest và early detection khỏi các tác vụ nặng như AI, enrichment, market refresh và OSM processing.", "Dùng bounded queue và backpressure; khi storage chậm, hệ thống giữ dữ liệu và giảm tốc độ nhận thay vì âm thầm drop raw log.", "Chỉ ACK raw event sau khi event đã được xử lý bền vững; checkpoint và replay được thiết kế idempotent để tránh duplicate.", "Phân tách immutable event trong ClickHouse với mutable current state trong PostgreSQL."]:
        b(x)

    h1("3. Công nghệ và thiết kế dữ liệu")
    h2("3.1. ClickHouse – event storage")
    p("Bảng http_events lưu event HTTP với event_time, ingested_at, dataset_id, source_id, source_offset, event_id, địa chỉ IP, method, path, status, bytes, referer, user-agent và raw line. Bảng dùng ReplacingMergeTree, phân vùng theo tháng và sắp xếp theo dataset/event để hỗ trợ truy vấn lịch sử và xử lý idempotent.")
    h2("3.2. PostgreSQL – state và read-model")
    p("PostgreSQL lưu các dữ liệu có thể thay đổi theo thời gian: ip_profiles, ip_observations_state, rule_firing_state, alert_outbox, feature theo phút, AI model state và ip_ai_scores. Checkpoint của log source và processed batch được lưu bền vững, cho phép tiếp tục xử lý sau reconnect hoặc restart.")
    h2("3.3. Chuẩn hóa dữ liệu")
    p("Raw access-log line được parse thành cấu trúc thống nhất. Path được canonicalize để giảm sai lệch do query string, encoding hoặc biến thể URL; nhờ đó traffic analytics, rule detection và Rare Path có thể dùng cùng một biểu diễn dữ liệu.")

    h1("4. Quy trình xử lý dữ liệu realtime")
    p("Collector nhận log qua WebSocket và chuyển qua Fast Detection trước khi đưa vào storage path. Fast Detection chỉ thực hiện thao tác nhẹ, không chờ database hay network, nên không làm nghẽn hot path.")
    body.append(table([
        ["Bước", "Xử lý", "Kết quả"],
        ["1", "Nhận raw log qua WebSocket", "Dòng log và source offset"],
        ["2", "Parse và normalize", "Event HTTP chuẩn hóa"],
        ["3", "Fast Detection / correlation ngắn hạn", "Preliminary alert nếu có"],
        ["4", "Bounded storage queue", "Backpressure khi quá tải"],
        ["5", "Persist ClickHouse/PostgreSQL", "Event, feature, state và checkpoint"],
        ["6", "Deep/background analysis", "Enrichment, Rare Path, AI, market data"],
        ["7", "SSE/Telegram/API", "Cảnh báo và dashboard realtime"],
    ], [700, 4600, 3800]))
    h2("Early Alert và Final Alert")
    p("Early Alert có trạng thái preliminary, được tạo nhanh từ các marker có độ tin cậy cao như /.env, /.git, wp-config.php, phpmyadmin và adminer. Correlation theo IP sử dụng cửa sổ TTL giới hạn; cooldown theo cặp (IP, rule) giúp tránh alert storm. Final Alert vẫn lấy alert_outbox trong PostgreSQL làm nguồn durable, do đó preliminary alert không thay đổi classification, checkpoint hoặc replay state.")

    h1("5. Phát hiện hành vi và threat intelligence")
    h2("5.1. Rule-based detection")
    p("Các rule YAML trong thư mục rules mô tả những hành vi đã biết: WEB-SENSITIVE-001 cho sensitive path, WEB-BRUTE-001 cho brute-force, WEB-BURST-001 cho request burst, WEB-SCAN-001 cho path scan, WEB-4XX-001 cho nhiều lỗi HTTP và WEB-BOT-001 cho bot traffic. Rule engine lưu firing state để áp dụng window, cooldown và replay nhất quán.")
    h2("5.2. Rare Path và Isolation Forest")
    p("Rare Path phân tích lịch sử path để tìm URL ít xuất hiện hoặc được truy cập bởi rất ít IP. Isolation Forest là Stage 2 periodic worker độc lập với Collector; đặc trưng theo phút được dùng để phát hiện anomaly thống kê. Kết quả được lưu ở ip_ai_scores, có model version, confidence và evidence. API không chạy model trong request; IP chưa có snapshot hợp lệ trả ai_status là pending.")
    body.append(table([
        ["Lớp", "Tín hiệu", "Mục đích"],
        ["Fast Detection", "Sensitive marker, burst, wp-login, path diversity", "Cảnh báo sớm, độ trễ thấp"],
        ["Rules", "Windowed counts theo IP/path/status", "Phát hiện pattern đã biết"],
        ["Rare Path", "Độ hiếm của path và số IP đã truy cập", "Tìm probing bất thường"],
        ["Isolation Forest", "Feature theo phút và anomaly score", "Bổ sung tín hiệu thống kê"],
        ["Threat intelligence", "Geo, ASN, Tor, VPN, proxy, hosting, abuse", "Bổ sung context và evidence"],
    ], [2200, 4200, 2700]))
    h2("5.3. Threat intelligence")
    p("IP được enrich từ các provider và dataset cục bộ. Kết quả gồm vị trí, ASN/tổ chức, loại network, trạng thái privacy network, reputation và nguồn dữ liệu. Intelligence chỉ là context/supporting evidence; hệ thống không kết luận một IP là malicious chỉ vì IP thuộc VPN, hosting hoặc một quốc gia cụ thể.")

    h1("6. Chấm điểm IP và phân loại rủi ro")
    p("IP score kết hợp behavior score với network identity, trusted network, conflict context, AI anomaly và campaign correlation. Behavior là thành phần chính; các tín hiệu network và AI giúp giải thích bối cảnh, không thay thế bằng chứng hành vi.")
    body.append(table([
        ["Nhóm", "Ý nghĩa", "Tác động"],
        ["A – Behavior", "Request, probing, burst, bot, HTTP errors", "0–100"],
        ["B – Network identity", "Tor, proxy, VPN, hosting", "Tối đa +25"],
        ["C – Trusted network", "Tổ chức/mạng tin cậy và hành vi thấp", "Tối đa −20"],
        ["D – Conflict context", "Bối cảnh địa chính trị khi đã có behavior đáng ngờ", "+0 đến +5"],
        ["E – AI anomaly", "Anomaly đủ mạnh từ Isolation Forest", "+8"],
        ["F – Campaign correlation", "IP cùng ASN có path/hành vi tương đồng", "+0 đến +5"],
    ], [2400, 5600, 1800]))
    p("Network component được giới hạn để tránh cộng dồn quá mức: Tor +15, Proxy +10, VPN +8, Hosting +5 và tổng nhóm B không vượt quá +25. Evidence được lưu cùng kết quả nhằm trả lời câu hỏi vì sao IP đạt mức đánh giá hiện tại.")
    body.append(table([
        ["Classification", "Điều kiện khái quát"],
        ["UNKNOWN", "Chưa đủ dữ liệu và chưa có behavior/network/AI signal đáng kể"],
        ["GOOD", "Chưa đạt ngưỡng đáng ngờ"],
        ["LOW", "Score từ 10 đến 29"],
        ["MEDIUM", "Score từ 30 đến 59 hoặc AI anomaly đủ điều kiện"],
        ["CRITICAL", "Score từ 60 hoặc hard behavior như sensitive probing"],
    ], [2200, 7600]))

    h1("7. Region / Market Intelligence")
    p("Region score là chức năng độc lập với security score. Từ quốc gia suy ra từ IP, hệ thống kết hợp dữ liệu World Bank WDI và UN Comtrade để ước lượng tiềm năng thị trường. WDI cung cấp GDP, GDP/người, dân số, nhập khẩu và chỉ số phát triển; Comtrade cung cấp nhu cầu nhập khẩu, tăng trưởng, độ ổn định và cơ cấu sản phẩm, trong đó có nhóm máy chế biến gỗ.")
    p("Công thức tổng quát của module là: Economic Potential = 40% Market Capacity + 60% Industrial Fit; Market Score = 40% Economic Potential + 60% Machine Demand. Kết quả nhằm hỗ trợ phân tích cơ hội theo khu vực, không được trộn trực tiếp vào security risk của IP.")
    h2("Độ tin cậy và cập nhật")
    p("Dữ liệu thị trường được làm mới bằng các worker riêng như worldbank_update, comtrade_update, market_refresh và local_opportunity_refresh. Các nguồn, thời điểm cập nhật và auxiliary evidence cần được lưu kèm read-model để người dùng có thể kiểm tra nguồn gốc của điểm thị trường.")

    h1("8. API, dashboard và vận hành")
    p("FastAPI khởi tạo PostgreSQL pool, WebSocket Collector, AI runtime, classification watcher và coverage consumer trong lifespan. Các router cung cấp health check, traffic analytics, IP state/detail, region intelligence và realtime stream. Middleware đo thời gian xử lý qua header X-Process-Time-ms.")
    h2("Giao diện")
    for x in ["Dashboard tổng quan hiển thị traffic, cảnh báo và chỉ số hệ thống.", "Trang IP detail hiển thị profile, score, classification, AI status và evidence.", "Trang region detail hiển thị dữ liệu địa lý và market opportunity.", "SSE cung cấp cập nhật realtime; Telegram là kênh thông báo bổ sung."]:
        b(x)
    h2("Vận hành an toàn")
    p("Các workload nền có thể bị giới hạn bởi workload governor. Queue có kích thước hữu hạn và metric degraded khi early-alert queue overflow. Advisory lock ngăn AI cycle chạy chồng; state được persist để có thể đọc lại sau restart. Các nguyên tắc này giúp hệ thống giữ ingest, checkpoint và alert path hoạt động khi phân tích chuyên sâu chậm.")

    h1("9. Kiểm thử và đánh giá")
    p("Repository có bộ kiểm thử tự động bao phủ detection core, rule fixtures, replay consistency, failure injection, WebSocket collector, early-alert pipeline, AI runtime, market opportunity, geography, traffic analytics, API read-model và workload governor. Khi kiểm tra tại thời điểm lập báo cáo, thư mục tests có 205 hàm test được khai báo.")
    body.append(table([
        ["Nhóm kiểm thử", "Nội dung đánh giá"],
        ["Detection", "Sensitive marker, burst, brute-force, scan, 4xx và rule parity"],
        ["Reliability", "Reconnect, replay, checkpoint, duplicate invariant và failure injection"],
        ["Realtime", "Early alert, SSE/Telegram và isolation giữa AI với ingest"],
        ["AI", "Model state, advisory lock, pending status, score persistence và phase acceptance"],
        ["Data / market", "Geo foundation, enrichment, region, World Bank/Comtrade và local opportunity"],
        ["API / UI", "IP detail, regions, traffic, health và session cache"],
    ], [2500, 7300]))
    p("Các acceptance test của AI dùng artificial slow AI để chứng minh AI worker chậm không làm dừng ingest, Early Alert, storage và checkpoint; không dùng sleep để che race condition. Đây là tiêu chí quan trọng đối với hệ thống realtime.")

    h1("10. Kết quả, hạn chế và hướng phát triển")
    h2("Kết quả đạt được")
    for x in ["Xây dựng pipeline từ raw log đến dashboard với các lớp xử lý tách biệt.", "Có early detection độ trễ thấp và durable alert path.", "Bảo đảm replay/idempotency và backpressure cho dữ liệu quan trọng.", "Kết hợp behavior, network intelligence, AI anomaly và evidence trong một IP read-model.", "Mở rộng từ security monitoring sang region/market intelligence bằng dữ liệu kinh tế và thương mại."]:
        b(x)
    h2("Hạn chế")
    for x in ["Chất lượng kết quả phụ thuộc độ đầy đủ và độ mới của provider Geo/ASN/privacy/reputation.", "Isolation Forest cần đủ dữ liệu lịch sử và cần theo dõi drift, false positive theo từng dataset.", "Market score là chỉ số hỗ trợ quyết định, chưa thay thế nghiên cứu thị trường hoặc xác minh nhu cầu thực tế.", "Dashboard hiện là frontend HTML/CSS/JavaScript, cần tiếp tục hoàn thiện UX và quản trị quyền truy cập khi triển khai production."]:
        b(x)
    h2("Hướng phát triển")
    for x in ["Xây dựng Unified Evidence để liên kết rule, AI, provider và market evidence theo nguồn/thời gian.", "Phát triển Local AI Reasoner có giải thích, kiểm soát phiên bản và cơ chế đánh giá false positive.", "Bổ sung tiềm năng mua hàng ở cấp thành phố bằng H3/OSM, dữ liệu địa phương và auxiliary evidence.", "Hoàn thiện observability: metric queue depth, lag, provider health, replay rate và alert delivery.", "Bổ sung authentication, authorization và audit log cho API/dashboard khi triển khai nhiều người dùng."]:
        b(x)

    h1("Tài liệu tham khảo")
    refs = [
        "[1] README và mã nguồn repository IP Intelligence, Group 7, 2026.",
        "[2] FastAPI Documentation, https://fastapi.tiangolo.com/.",
        "[3] ClickHouse Documentation, https://clickhouse.com/docs/.",
        "[4] PostgreSQL Documentation, https://www.postgresql.org/docs/.",
        "[5] scikit-learn – IsolationForest, https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html.",
        "[6] World Bank – World Development Indicators, https://databank.worldbank.org/source/world-development-indicators.",
        "[7] UN Comtrade Database, https://comtradeplus.un.org/.",
        "[8] MITRE ATT&CK Framework, https://attack.mitre.org/.",
    ]
    for ref in refs:
        body.append(paragraph(ref, size=21, after=90))

    if sect_pr is not None:
        body.append(deepcopy(sect_pr))
    return body


def main():
    with ZipFile(SOURCE, "r") as zin:
        data = {name: zin.read(name) for name in zin.namelist()}
    root = ET.fromstring(data["word/document.xml"])
    old_body = root.find(tag("body"))
    root.remove(old_body)
    root.append(build_body(old_body))
    data["word/document.xml"] = ET.tostring(root, encoding="UTF-8", xml_declaration=True)
    with ZipFile(TMP, "w", ZIP_DEFLATED) as zout:
        for name, content in data.items():
            zout.writestr(name, content)
    os.replace(TMP, SOURCE)
    print(f"updated {SOURCE}")


if __name__ == "__main__":
    main()
