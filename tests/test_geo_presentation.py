from pathlib import Path


IP_DETAIL = Path("app/web/templates/ip_detail.html").read_text()


def test_geo_presentation_uses_candidate_for_probable_country_only_in_the_ui():
    assert "const top=candidates[0]?.value||null" in IP_DETAIL
    assert "const displayCode=resolved||top||null" in IP_DETAIL
    assert "const displayName=displayCode?countryName(displayCode)" in IP_DETAIL
    assert "canonical.resolved?.country_code" in IP_DETAIL
    assert "countryView.status" in IP_DETAIL


def test_geo_presentation_keeps_disputed_and_unknown_distinct():
    assert "status==='disputed'?'Disputed':'Unknown'" in IP_DETAIL
    assert "Candidates:" in IP_DETAIL


def test_geo_presentation_does_not_promote_canonical_country():
    assert "const displayCode=resolved||top||null" in IP_DETAIL
    assert "canonical.resolved?.country_code||location?.country_code||null" in IP_DETAIL
    assert "cityCountry=(cityCandidate?.country_codes||[])[0]||cityCandidate?.country_code||cityCandidate?.country||null" in IP_DETAIL
    assert "Cross-level location conflict" in IP_DETAIL


def test_geo_presentation_exposes_cross_level_and_private_states():
    assert "Cross-level location conflict" in IP_DETAIL
    assert "Geolocation is not applicable to non-public addresses" in IP_DETAIL
    assert "privateAddress&&countryView.status==='resolved'" in IP_DETAIL
    assert "privateAddress?'':`<section class=\"card\"" in IP_DETAIL


def test_ip_intelligence_uses_top_probable_country_candidate_for_display():
    dashboard = Path("app/web/static/dashboard.js").read_text()
    assert "const topCountryCandidate=location=>" in dashboard
    assert "x.country_code||topCountry||'—'" in dashboard
    assert "d.country_code||topCountry||'—'" in dashboard
    assert "countryNameFromCode(code)||((rawCountry" in dashboard


def test_ip_intelligence_normalizes_country_code_to_display_name():
    dashboard = Path("app/web/static/dashboard.js").read_text()
    assert "countryNameFromCode(code)||((rawCountry" in dashboard
