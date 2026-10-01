from app.core.country_demand import CountryDemandConfig, aggregate_country_demand, aggregate_session_observations, build_country_opportunities, exclusion_state


def event(country="TH", session="s1", visitor="v1", **extra):
    return {"country_code": country, "session_id": session, "visitor_id": visitor, "engaged_session_depth": 2, **extra}


def test_hard_exclusions_and_soft_flags_are_separate():
    assert exclusion_state(event(is_tor=True)) == ("tor_exit", False)
    assert exclusion_state(event(is_vpn=True)) == (None, True)
    assert exclusion_state(event(is_hosting=True, business_isp=False)) == ("datacenter_hosting", False)
    assert exclusion_state(event(is_hosting=True, business_isp=True)) == (None, False)


def test_country_snapshot_keeps_excluded_counts_and_applies_sample_gate():
    current = [event(session=f"s{i}", visitor=f"v{i}") for i in range(3)]
    current += [event(session="bad", visitor="bad", is_tor=True), event(session="vpn", visitor="vpn", is_vpn=True)]
    previous = [event(session=f"p{i}", visitor=f"p{i}") for i in range(3)]
    result = aggregate_country_demand(current, previous, config=CountryDemandConfig(min_sample_size=3))
    country = result["countries"][0]
    assert country["qualified_sessions"] == 4
    assert country["excluded"] == {"tor_exit": 1}
    assert country["sample_size_sufficient"] is True
    assert country["confidence"] == "MEDIUM"


def test_missing_previous_sample_never_creates_trend_or_signal():
    result = aggregate_country_demand([event(session=f"s{i}") for i in range(4)], [], config=CountryDemandConfig(min_sample_size=3))
    country = result["countries"][0]
    assert country["trend_pct"] is None
    assert country["trend"] == "INSUFFICIENT_DATA"
    assert country["signal"] == "INSUFFICIENT_DATA"
    assert country["explanation"] == "Insufficient sample for a reliable trend."


def test_signal_uses_percentile_volume_not_absolute_country_size():
    current = [event(country="TH", session=f"th{i}", visitor=f"th{i}") for i in range(20)]
    current += [event(country="MY", session=f"my{i}", visitor=f"my{i}") for i in range(5)]
    previous = [event(country="TH", session=f"pth{i}", visitor=f"pth{i}") for i in range(20)]
    previous += [event(country="MY", session=f"pmy{i}", visitor=f"pmy{i}") for i in range(5)]
    result = aggregate_country_demand(current, previous, config=CountryDemandConfig(min_sample_size=1))
    by_code = {item["country_code"]: item for item in result["countries"]}
    assert by_code["TH"]["volume_tier"] == "HIGH"
    assert by_code["MY"]["volume_tier"] == "MEDIUM"


def test_ip_is_not_used_as_synthetic_identity():
    current = [{"country_code": "VN", "ip": "203.0.113.10", "engaged_session_depth": 1}]
    previous = [{"country_code": "VN", "ip": "203.0.113.11", "engaged_session_depth": 1}]
    country = aggregate_country_demand(current, previous, config=CountryDemandConfig(min_sample_size=1))["countries"][0]
    assert country["qualified_requests"] == 1
    assert country["qualified_sessions"] == 0
    assert country["qualified_visitors"] == 0
    assert country["identity_coverage"] == 0.0
    assert country["sample_size_sufficient"] is False
    assert country["signal"] == "INSUFFICIENT_DATA"


def test_country_opportunity_keeps_small_samples_as_early_signal():
    result = build_country_opportunities(
        {"7d": {"countries": [{"country_code": "DE", "qualified_requests": 2}]},
         "30d": {"countries": [{"country_code": "DE", "qualified_requests": 4, "identity_coverage": 0}]},
         "90d": {"countries": [{"country_code": "DE", "qualified_requests": 7}]}},
        {"DE": {"country_code": "DE", "country_name": "Germany", "market_score": 84}},
    )
    country = result["countries"][0]
    assert country["evidence_level"] == "VERY_LOW"
    assert country["opportunity_state"] == "EMERGING"
    assert country["quality_score"] is None
    assert country["opportunity_score"] is None
    assert country["opportunity_status"] == "WATCH"


def test_country_opportunity_does_not_invent_market_score():
    result = build_country_opportunities(
        {"7d": None, "30d": {"countries": [{"country_code": "SG", "qualified_requests": 40}]}, "90d": None},
        {},
    )
    country = result["countries"][0]
    assert country["market_score"] is None
    assert country["opportunity_score"] is None
    assert country["opportunity_state"] == "INVESTIGATE"


def test_country_opportunity_omits_market_only_profiles():
    result = build_country_opportunities(
        {"7d": None, "30d": {"countries": [{"country_code": "US", "qualified_requests": 2}]}, "90d": None},
        {"US": {"country_code": "US", "market_score": 80}, "DE": {"country_code": "DE", "market_score": 90}},
    )
    assert [item["country_code"] for item in result["countries"]] == ["US"]


def test_country_opportunity_uses_selected_period_for_rows_and_score():
    snapshots = {
        "7d": {"countries": [{"country_code": "US", "qualified_requests": 2}]},
        "30d": {"countries": [{"country_code": "US", "qualified_requests": 21}, {"country_code": "SG", "qualified_requests": 2}]},
        "90d": {"countries": [{"country_code": "US", "qualified_requests": 21}, {"country_code": "SG", "qualified_requests": 2}]},
    }
    result = build_country_opportunities(snapshots, {"US": {"market_score": 80}}, period="7d")
    assert result["period"] == "7d"
    assert [item["country_code"] for item in result["countries"]] == ["US"]
    assert result["countries"][0]["traffic_7d"] == 2
    assert "observed in 7d" in result["countries"][0]["explanation"]


def test_opportunity_shrinks_low_confidence_demand_to_neutral():
    result = build_country_opportunities({"30d": {"countries": [{"country_code": "SG", "qualified_requests": 10, "country_demand_score": 85, "demand_confidence": 0.10}]}}, {"SG": {"country_name": "Singapore", "market_score": 91}})["countries"][0]
    assert result["adjusted_demand_score"] == 53.5
    assert result["opportunity_score"] == 76.0
    assert result["opportunity_status"] == "EMERGING"


def test_opportunity_rewards_high_confidence_demand():
    result = build_country_opportunities({"30d": {"countries": [{"country_code": "DE", "qualified_requests": 10, "country_demand_score": 74, "demand_confidence": 0.70}]}}, {"DE": {"country_name": "Germany", "market_score": 82}})["countries"][0]
    assert result["adjusted_demand_score"] == 66.8
    assert result["opportunity_score"] == 75.9
    assert result["opportunity_status"] == "PRIORITIZE"


def test_vietnam_qualified_http_requests_conserve_across_provinces_and_unmapped():
    observations = [
        {"country_code": "VN", "session_id": "s1", "city_geo_unit_id": "79"},
        {"country_code": "VN", "session_id": "s1", "city_geo_unit_id": "79"},
        {"country_code": "VN", "session_id": "s2", "city_geo_unit_id": None},
        {"country_code": "VN", "session_id": "s3", "city_geo_unit_id": "01", "geo_conflict": True},
    ]

    row = aggregate_country_demand(aggregate_session_observations(observations), []) ["countries"][0]

    assert row["qualified_requests"] == 3
    assert row["qualified_http_requests"] == 4
    assert row["city_traffic"] == {
        "provinces": [{"geo_unit_id": "79", "qualified_http_requests": 2}],
        "unmapped_qualified_http_requests": 2,
        "total_qualified_http_requests": 4,
        "conservation": True,
    }


def test_country_opportunities_expose_selected_period_http_and_city_traffic():
    snapshots = {
        "7d": {"countries": [{"country_code": "VN", "qualified_requests": 2,
                               "qualified_http_requests": 9,
                               "city_traffic": {"total_qualified_http_requests": 9}}]},
        "30d": {"countries": [{"country_code": "VN", "qualified_requests": 5,
                                "qualified_http_requests": 22,
                                "city_traffic": {"total_qualified_http_requests": 22}}]},
        "90d": None,
    }

    row = build_country_opportunities(snapshots, {}, period="7d")["countries"][0]

    assert row["traffic_7d"] == 2
    assert row["qualified_http_requests"] == 9
    assert row["city_traffic"]["total_qualified_http_requests"] == 9


def test_vietnam_city_attribution_requires_consistent_resolved_location():
    from app.services.country_demand import _normalize_observation

    profile = {
        "country_code": "VN", "city": "Ho Chi Minh City", "latitude": 10.8, "longitude": 106.6,
        "location_disputed": False,
        "network_location": {"city_status": "probable", "city_conflict": False,
                              "coordinate_conflict": False, "disputed": False},
    }

    normalized = _normalize_observation({"src_ip": "203.0.113.1", "cf_country": "VN"}, {"203.0.113.1": profile})
    no_coordinates = _normalize_observation(
        {"src_ip": "203.0.113.1", "cf_country": "VN"},
        {"203.0.113.1": {**profile, "latitude": None}},
    )
    country_conflict = _normalize_observation(
        {"src_ip": "203.0.113.1", "cf_country": "US"}, {"203.0.113.1": profile},
    )

    assert normalized["city_geo_unit_id"] == "79"
    assert no_coordinates["city_geo_unit_id"] is None
    assert country_conflict["city_geo_unit_id"] is None


def test_vietnam_dbip_district_maps_through_agreeing_province_parent():
    from app.services.country_demand import _normalize_observation

    ip = "203.0.113.2"
    profile = {
        "country_code": "VN", "city": None, "latitude": None, "longitude": None,
        "location_disputed": True,
        "network_location": {
            "geo": {"city": {
                "status": "disputed", "conflict": True, "coordinate_conflict": True,
                "candidates": {
                    "dbip_city": {"city": "Quan Binh Thanh", "state": "Ho Chi Minh City (HCMC)",
                                  "country_code": "VN", "valid": True},
                    "geolite2_city": {"city": "Ho Chi Minh City", "state": "Ho Chi Minh",
                                       "country_code": "VN", "valid": True},
                },
            }},
        },
    }

    normalized = _normalize_observation({"src_ip": ip, "cf_country": "VN"}, {ip: profile})

    assert normalized["city_geo_unit_id"] == "79"


def test_unseen_future_city_label_maps_by_recognized_vietnam_parent():
    from app.services.country_demand import _normalize_observation

    ip = "203.0.113.6"
    profile = {
        "country_code": "VN", "city": None,
        "network_location": {"geo": {"city": {"candidates": {
            "dbip_city": {"city": "Unlisted District Name", "state": "Da Nang City",
                          "country_code": "VN", "valid": True},
        }}}},
    }

    normalized = _normalize_observation({"src_ip": ip, "cf_country": "VN"}, {ip: profile})

    assert normalized["city_geo_unit_id"] == "48"


def test_vietnam_dbip_district_stays_unmapped_when_parent_missing_or_disagrees():
    from app.services.country_demand import _normalize_observation

    ip = "203.0.113.3"
    base = {
        "country_code": "VN", "city": None, "latitude": None, "longitude": None,
        "network_location": {"geo": {"city": {"candidates": {
            "dbip_city": {"city": "Quan Binh Thanh", "state": "Ho Chi Minh City (HCMC)",
                          "country_code": "VN", "valid": True},
        }}}},
    }
    missing_parent = {**base, "network_location": {"geo": {"city": {"candidates": {
        "dbip_city": {"city": "Quan Binh Thanh", "country_code": "VN", "valid": True},
    }}}}}
    conflicting_parent = {**base, "network_location": {"geo": {"city": {"candidates": {
        "dbip_city": {"city": "Quan Binh Thanh", "state": "Ho Chi Minh City (HCMC)",
                      "country_code": "VN", "valid": True},
        "geolite2_city": {"city": "Hanoi", "state": "Hanoi", "country_code": "VN", "valid": True},
    }}}}}

    assert _normalize_observation({"src_ip": ip, "cf_country": "VN"}, {ip: missing_parent})["city_geo_unit_id"] is None
    assert _normalize_observation({"src_ip": ip, "cf_country": "VN"}, {ip: conflicting_parent})["city_geo_unit_id"] is None


def test_vietnam_dbip_district_stays_unmapped_when_geoip_country_candidates_conflict():
    from app.services.country_demand import _normalize_observation

    ip = "203.0.113.4"
    profile = {
        "country_code": "VN", "city": None,
        "network_location": {"geo": {"city": {"candidates": {
            "dbip_city": {"city": "Quan Binh Thanh", "state": "Ho Chi Minh City (HCMC)",
                          "country_code": "VN", "valid": True},
            "geolite2_city": {"city": "Somewhere", "state": "California",
                               "country_code": "US", "valid": True},
        }}}},
    }

    normalized = _normalize_observation({"src_ip": ip, "cf_country": "VN"}, {ip: profile})

    assert normalized["city_geo_unit_id"] is None


def test_vietnam_dbip_district_stays_unmapped_when_candidate_country_is_unknown():
    from app.services.country_demand import _normalize_observation

    ip = "203.0.113.5"
    profile = {
        "country_code": "VN", "city": None,
        "network_location": {"geo": {"city": {"candidates": {
            "dbip_city": {"city": "Quan Binh Thanh", "state": "Ho Chi Minh City (HCMC)",
                          "country_code": "VN", "valid": True},
            "geolite2_city": {"city": "Unresolved", "state": "Hanoi", "valid": True},
        }}}},
    }

    normalized = _normalize_observation({"src_ip": ip, "cf_country": "VN"}, {ip: profile})

    assert normalized["city_geo_unit_id"] is None
