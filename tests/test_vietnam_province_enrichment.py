import json
from types import SimpleNamespace
from pathlib import Path

from scripts.market.vietnam_province_enrichment import (
    OFFICIAL_PROVINCE_KCN_SOURCES,
    _number,
    _publish_payloads,
    _run_refresh,
    build_kcn_context,
    coverage_gate,
    parse_fdi_html,
    parse_fdi_stock_attachment,
    parse_fdi_stock_pdf_text,
    parse_hung_yen_kcn_html,
    parse_industrial_presence_attachment,
    parse_investvietnam_kcn_html,
    validate_industrial_presence_records,
)


def test_kcn_context_has_all_34_units_and_missing_is_null():
    rows = build_kcn_context("2026-01-01T00:00:00+00:00")
    assert len(rows) == 34
    assert all(row["industrial_park_count"] is None for row in rows)
    assert all("limitation" in row for row in rows)


def test_fdi_parser_never_infers_missing_provinces():
    raw = "<table><tr><th>STT</th><th>Địa phương</th><th>Tổng vốn đăng ký</th><th>Tăng/Giảm</th></tr><tr><td>1</td><td>Hà Nội</td><td>1.234,5</td><td>5,0%</td></tr></table>".encode()
    rows = parse_fdi_html(raw, "https://example.test", "2025", "now")
    assert len(rows) == 34
    assert all(row["manufacturing_fdi_usd_million"] is None for row in rows)


def test_fdi_stock_attachment_rejects_top10_or_partial_table():
    raw = "<table><tr><th>STT</th><th>Địa phương</th><th>Vốn</th></tr><tr><td>1</td><td>Hà Nội</td><td>100</td></tr></table>".encode()
    import pytest
    with pytest.raises(ValueError, match="incomplete"):
        parse_fdi_stock_attachment(raw, "https://fia.example/appendix-iii", "cumulative_to_2026-07-31", "now")


def test_fia_pdf_stock_parser_requires_34_rows_and_golden_anchors():
    lines = ["STT Địa Phương Số dự án Tổng vốn đầu tư (triệu USD)"]
    provinces = __import__('app.core.vietnam_geography', fromlist=['PROVINCES']).PROVINCES
    anchors = {"Hồ Chí Minh": (21308, 149050.87), "Bắc Ninh": (3664, 51469.26), "Hải Phòng": (2177, 47848.92)}
    total = 559238.87 - 2768.69
    rest = (total - sum(v[1] for v in anchors.values())) / 31
    for i, unit in enumerate(provinces, 1):
        projects, stock = anchors.get(unit['name'], (1, rest))
        lines.append(f"{i} {unit['name']} {projects} {stock:.2f} 1,0%")
    lines.insert(32, "27 Dầu khí 50 2768.69 0,5%")
    rows = parse_fdi_stock_pdf_text("\n".join(lines), "https://fia.example/appendix.pdf", "now")
    assert len(rows) == 34
    assert next(row for row in rows if row['province_name'] == 'Hồ Chí Minh')['fdi_stock_cumulative_usd_million'] == 149050.87


def test_industrial_presence_rejects_partial_table_and_keeps_proxy_semantics():
    raw = "<table><tr><th>Địa phương</th><th>Số xã</th><th>Tỷ lệ</th></tr><tr><td>Hà Nội</td><td>13</td><td>20,0</td></tr></table>".encode()
    import pytest
    with pytest.raises(ValueError, match="incomplete"):
        parse_industrial_presence_attachment(raw, "https://nso.example/table", "now")


def test_industrial_presence_validator_rejects_lost_zero_rows():
    rows = [{"geo_unit_id": str(i), "province_name": str(i), "communes_total": 10, "communes_with_industrial_park": 2, "commune_ip_presence_rate_pct": 20} for i in range(34)]
    rows[0]["communes_with_industrial_park"] = 20
    import pytest
    with pytest.raises(ValueError, match="impossible"):
        validate_industrial_presence_records(rows)


def test_official_kcn_page_only_populates_observed_fields():
    row = parse_hung_yen_kcn_html(b"<h1>Industrial parks in operation</h1><p>Total area: 100,5 (ha)</p><p>Total area: 20 ha</p>", "now")
    assert row["industrial_park_count"] == 2
    assert row["total_area_ha"] == 120.5
    assert row["occupancy_rate_pct"] is None


def test_hung_yen_duplicate_bilingual_block_is_counted_once():
    raw = b"<p>Total area: 100 ha</p><p>Total area: 20 ha</p><p>Total area: 100 ha</p><p>Total area: 20 ha</p>"
    row = parse_hung_yen_kcn_html(raw, "now")
    assert row["industrial_park_count"] == 2
    assert row["total_area_ha"] == 120


def test_coverage_gate_disables_comparison_below_threshold():
    rows = [{"x": 1}, {"x": None}]
    gate = coverage_gate(rows, ("x",))
    assert gate["coverage"]["x"] == 1
    assert gate["eligible_for_province_comparison"]["x"] is False
    assert gate["ranking_enabled"] is False


def test_fia_number_parser_handles_report_formats_and_direction():
    assert _number("7,633.5") == 7633.5
    assert _number("1.234,5") == 1234.5
    assert _number("↓ 349.6%") == -349.6
    assert _number("") is None
    assert _number(0) == 0.0


def test_official_province_page_parser_keeps_explicit_kcn_fields_only():
    source = OFFICIAL_PROVINCE_KCN_SOURCES["37"]
    raw = "<p>Hiện nay, tỉnh Ninh Bình có 13 khu công nghiệp đang hoạt động.</p><p>Tổng diện tích đất công nghiệp đã cho thuê đạt 1.564,9 ha, với tỷ lệ lấp đầy bình quân là 58,41%.</p>".encode()
    row = parse_investvietnam_kcn_html(raw, source, "now")
    assert row["industrial_park_count"] == 13
    assert row["leased_land_ha"] == 1564.9
    assert row["occupancy_rate_pct"] == 58.41
    assert row["total_area_ha"] is None


def test_province_page_uses_average_occupancy_not_first_park_rate():
    source = OFFICIAL_PROVINCE_KCN_SOURCES["37"]
    raw = "<p>Châu Sơn đạt tỷ lệ lấp đầy 100%.</p><p>Tỷ lệ lấp đầy bình quân là 58,41%.</p>".encode()
    row = parse_investvietnam_kcn_html(raw, source, "now")
    assert row["occupancy_rate_pct"] == 58.41


def test_refresh_keeps_existing_snapshots_when_any_source_batch_fails(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "scripts.market.vietnam_province_enrichment._fetch_fdi_batch",
        lambda _retrieved_at: ([], {"2025": {"status": "failed"}}, False),
    )
    monkeypatch.setattr(
        "scripts.market.vietnam_province_enrichment._load_fdi_stock",
        lambda _args, _retrieved_at: {},
    )
    monkeypatch.setattr(
        "scripts.market.vietnam_province_enrichment._load_industrial_presence",
        lambda _args, _retrieved_at: {},
    )
    monkeypatch.setattr(
        "scripts.market.vietnam_province_enrichment._fetch_kcn_context",
        lambda _retrieved_at: ([], None),
    )
    monkeypatch.setattr(
        "scripts.market.vietnam_province_enrichment._publish_payloads",
        lambda *_args: (_ for _ in ()).throw(AssertionError("partial batch must not publish")),
    )

    result = _run_refresh(SimpleNamespace(output=tmp_path))

    assert result["published"] is False
    assert result["fetch_status"]["2025"]["status"] == "failed"
    assert tmp_path.is_dir()


def test_publish_payloads_writes_four_separate_json_read_models(tmp_path):
    _publish_payloads(tmp_path, [{"period": "2025"}], {"2025": "loaded"},
                      {"records": []}, {"records": []}, [{"geo_unit_id": "33"}])

    paths = sorted(tmp_path.glob("*.json"))
    assert len(paths) == 4
    payloads = {path.name: json.loads(path.read_text(encoding="utf-8")) for path in paths}
    assert payloads["province_fdi_context.json"]["fetch_status"] == {"2025": "loaded"}
    assert payloads["province_industrial_park_context.json"]["records"] == [{"geo_unit_id": "33"}]
