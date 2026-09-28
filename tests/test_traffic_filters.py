from contextlib import contextmanager

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routers import traffic


class _Result:
    def fetchall(self):
        return [{"ip": "203.0.113.10"}, {"ip": "203.0.113.11"}]


class _Connection:
    def execute(self, *_args):
        return _Result()


def test_country_filter_loads_ips_for_include_and_exclude(monkeypatch):
    profiles = [
        {"ip": "203.0.113.10", "country_code": "US"},
        {"ip": "203.0.113.11", "country_code": "VN"},
        {"ip": "203.0.113.12", "country_code": None},
    ]

    @contextmanager
    def transaction():
        class Connection:
            def execute(self, sql, args=()):
                requested = args[0]
                if "country_code = %s" in sql:
                    matched = [row for row in profiles if row["country_code"] == requested]
                elif "country_code != %s OR country_code IS NULL" in sql:
                    matched = [row for row in profiles if row["country_code"] != requested or row["country_code"] is None]
                else:
                    raise AssertionError(f"Unexpected country predicate: {sql}")
                return type("Rows", (), {"fetchall": lambda self: matched})()

        yield Connection()

    monkeypatch.setattr(traffic.postgres_store, "transaction", transaction)

    assert traffic._country_ips("us", False) == ["203.0.113.10"]
    assert traffic._country_ips("us", True) == ["203.0.113.11", "203.0.113.12"]


def test_clickhouse_filter_receives_already_resolved_cohort(monkeypatch):
    from datetime import datetime, timezone
    from app.db import clickhouse

    class Client:
        def __init__(self):
            self.queries = []

        def query(self, sql, parameters=None):
            self.queries.append((sql, parameters))
            class Result:
                column_names = []
                result_rows = []
            return Result()

        def close(self):
            pass

    client = Client()
    monkeypatch.setattr(clickhouse, "connect", lambda: client)
    now = datetime.now(timezone.utc)
    clickhouse.traffic(now, now, 60, filter_type="classification", filter_value="low",
                       exclude=True, allowed_ips=["203.0.113.8"])
    assert client.queries
    assert all("src_ip IN {allowed_ips:Array(IPv6)}" in sql for sql, _ in client.queries)


@pytest.mark.parametrize(
    ("filter_type", "value", "exclude", "predicate"),
    [
        (None, None, False, None),
        ("ip", "198.51.100.1", False, "src_ip = {filter_value:IPv6}"),
        ("ip", "198.51.100.1", True, "src_ip != {filter_value:IPv6}"),
        ("path", "/wp-login.php", False, "path = {filter_value:String}"),
        ("path", "/wp-login.php", True, "path != {filter_value:String}"),
        ("country", "US", False, "src_ip IN {allowed_ips:Array(IPv6)}"),
        ("country", "US", True, "src_ip IN {allowed_ips:Array(IPv6)}"),
        ("classification", "critical", False, "src_ip IN {allowed_ips:Array(IPv6)}"),
        ("classification", "critical", True, "src_ip IN {allowed_ips:Array(IPv6)}"),
    ],
)
def test_clickhouse_filter_predicate_contract(filter_type, value, exclude, predicate):
    from datetime import datetime, timezone
    from app.db.clickhouse import _traffic_filter

    start = datetime(2026, 9, 1, 10, 0, 30, tzinfo=timezone.utc)
    end = datetime(2026, 9, 1, 10, 1, 30, tzinfo=timezone.utc)
    where, parameters = _traffic_filter(
        start, end, "live", filter_type, value, exclude, ["203.0.113.9"]
    )
    assert (predicate in where) if predicate else "filter_value" not in where and "allowed_ips" not in where
    assert parameters["start"] == start
    assert parameters["end"] == end
    if filter_type in {"ip", "path"}:
        assert parameters["filter_value"] == value or filter_type == "ip" and parameters["filter_value"] == "::ffff:198.51.100.1"
    if filter_type in {"country", "classification"}:
        assert parameters["allowed_ips"] == ["203.0.113.9"]


@pytest.mark.parametrize(
    ("filter_type", "filter_value", "exclude", "expected_ips"),
    [
        (None, None, False, {"198.51.100.1", "2001:db8::2", "203.0.113.3", "203.0.113.4", "203.0.113.5"}),
        ("ip", "198.51.100.1", False, {"198.51.100.1"}),
        ("ip", "198.51.100.1", True, {"2001:db8::2", "203.0.113.3", "203.0.113.4", "203.0.113.5"}),
        ("path", "/wp-login.php", False, {"198.51.100.1", "2001:db8::2"}),
        ("path", "/wp-login.php", True, {"203.0.113.3", "203.0.113.4", "203.0.113.5"}),
        ("path", "/a%2Fb", False, {"203.0.113.4"}),
        ("path", "/unicode/đường-dẫn", False, {"203.0.113.5"}),
        ("country", "US", False, {"198.51.100.1"}),
        ("country", "US", True, {"2001:db8::2", "203.0.113.3", "203.0.113.4", "203.0.113.5"}),
        ("classification", "critical", False, {"198.51.100.1"}),
        ("classification", "critical", True, {"2001:db8::2", "203.0.113.3", "203.0.113.4", "203.0.113.5"}),
        ("path", "/foo?a=1&b=2", False, {"203.0.113.3"}),
    ],
)
def test_traffic_api_composes_filter_exact_cohort_and_summary(
    monkeypatch, filter_type, filter_value, exclude, expected_ips
):
    """Exercise the HTTP query contract through route, ClickHouse, and summary boundaries."""
    from collections import Counter

    events = [
        {"ip": "198.51.100.1", "path": "/wp-login.php"},
        {"ip": "198.51.100.1", "path": "/wp-login.php"},  # repeated event remains one donut identity
        {"ip": "2001:db8::2", "path": "/wp-login.php"},
        {"ip": "203.0.113.3", "path": "/foo?a=1&b=2"},
        {"ip": "203.0.113.4", "path": "/a%2Fb"},
        {"ip": "203.0.113.5", "path": "/unicode/đường-dẫn"},
    ]
    labels = {
        "198.51.100.1": "critical", "2001:db8::2": "unknown", "203.0.113.3": "low",
        "203.0.113.4": "good", "203.0.113.5": "medium",
    }
    resolved_cohorts = {
        ("country", "US", False): ["198.51.100.1"],
        ("country", "US", True): ["2001:db8::2", "203.0.113.3", "203.0.113.4", "203.0.113.5"],
        ("classification", "critical", False): ["198.51.100.1"],
        ("classification", "critical", True): ["2001:db8::2", "203.0.113.3", "203.0.113.4", "203.0.113.5"],
    }
    observed = {}

    def resolve_country(value, excluded):
        return resolved_cohorts[("country", value, excluded)]

    def resolve_classification(value, excluded):
        return resolved_cohorts[("classification", value, excluded)]

    def fake_clickhouse(start, end, bucket, *, dataset_id, filter_type, filter_value, exclude, allowed_ips):
        observed.update(start=start, end=end, bucket=bucket, dataset_id=dataset_id,
                        filter_type=filter_type, filter_value=filter_value, exclude=exclude,
                        allowed_ips=allowed_ips)
        matching = events
        if filter_type == "ip":
            matching = [event for event in events if (event["ip"] == filter_value) != exclude]
        elif filter_type == "path":
            matching = [event for event in events if (event["path"] == filter_value) != exclude]
        elif filter_type in {"country", "classification"}:
            allowed = set(allowed_ips or [])
            matching = [event for event in events if event["ip"] in allowed]
        cohort = sorted({event["ip"] for event in matching})
        observed["cohort"] = cohort
        return {
            "_cohort_ips": cohort,
            "total_requests": len(matching),
            "unique_ips": len(cohort),
            "top_ips": [{"ip": ip, "requests": sum(row["ip"] == ip for row in matching)} for ip in cohort],
            "top_paths": [],
        }

    class SummaryRepository:
        def classification_summary_for_ips(self, ips):
            counts = Counter(labels[ip] for ip in set(ips))
            keys = ("critical", "medium", "low", "good", "unknown")
            return {"total_ips": len(set(ips)), "classification": {key: counts[key] for key in keys}}

        def risk_traffic_series(self, *_args, **_kwargs):
            return []

    monkeypatch.setattr(traffic, "_country_ips", resolve_country)
    monkeypatch.setattr(traffic, "_classification_ips", resolve_classification)
    monkeypatch.setattr(traffic.clickhouse_store, "traffic", fake_clickhouse)
    monkeypatch.setattr(traffic, "StateRepository", SummaryRepository)
    app = FastAPI()
    app.include_router(traffic.router)

    params = {"range": "1h", "source": "stream"}
    if filter_type:
        params.update(filter_type=filter_type, filter_value=filter_value, exclude=str(exclude).lower())
    response = TestClient(app).get("/api/analytics/traffic", params=params)

    assert response.status_code == 200
    body = response.json()
    assert set(observed["cohort"]) == expected_ips
    assert observed["filter_type"] == filter_type
    assert observed["filter_value"] == filter_value
    assert observed["exclude"] is exclude
    assert body["unique_ips"] == len(expected_ips)
    summary = body["classification_summary"]
    assert summary["total_ips"] == len(expected_ips)
    assert sum(summary["classification"].values()) == summary["total_ips"]
    assert body["filter"] == (
        {"type": filter_type, "value": filter_value, "exclude": exclude} if filter_type else None
    )
    assert Counter(row["ip"] for row in body["top_ips"]) == Counter(expected_ips)
    assert "_cohort_ips" not in body


def test_classification_filter_uses_resolved_membership_but_current_donut_label(monkeypatch):
    """Membership is resolved first; the donut reflects current PG state read afterward."""
    from collections import Counter

    resolved_critical_cohort = ["203.0.113.9"]
    observed = {}

    def resolve_classification(label, exclude):
        assert (label, exclude) == ("critical", False)
        return resolved_critical_cohort

    def clickhouse_traffic(*_args, filter_type, filter_value, allowed_ips, **_kwargs):
        observed.update(filter_type=filter_type, filter_value=filter_value, allowed_ips=list(allowed_ips))
        assert allowed_ips == resolved_critical_cohort
        return {"_cohort_ips": ["203.0.113.9"], "total_requests": 1, "unique_ips": 1}

    class SummaryRepository:
        def classification_summary_for_ips(self, ips):
            assert ips == resolved_critical_cohort
            # The row changed after filter membership resolution and before this read.
            current_label = "medium"
            counts = Counter([current_label])
            return {
                "total_ips": 1,
                "classification": {key: counts[key] for key in ("critical", "medium", "low", "good", "unknown")},
            }

        def risk_traffic_series(self, *_args, **_kwargs):
            return []

    monkeypatch.setattr(traffic, "_classification_ips", resolve_classification)
    monkeypatch.setattr(traffic.clickhouse_store, "traffic", clickhouse_traffic)
    monkeypatch.setattr(traffic, "StateRepository", SummaryRepository)
    app = FastAPI()
    app.include_router(traffic.router)
    response = TestClient(app).get(
        "/api/analytics/traffic",
        params={"range": "1h", "filter_type": "classification", "filter_value": "critical"},
    )

    assert response.status_code == 200
    body = response.json()
    assert observed == {
        "filter_type": "classification", "filter_value": "critical",
        "allowed_ips": resolved_critical_cohort,
    }
    assert body["filter"] == {"type": "classification", "value": "critical", "exclude": False}
    assert body["classification_summary"] == {
        "total_ips": 1,
        "classification": {"critical": 0, "medium": 1, "low": 0, "good": 0, "unknown": 0},
    }


def test_traffic_projects_aggregates_and_closes_client(monkeypatch):
    from datetime import datetime, timezone

    from app.db import clickhouse

    class Result:
        def __init__(self, names, rows):
            self.column_names = names
            self.result_rows = rows

    class Client:
        def __init__(self):
            self.query_count = 0
            self.closed = False

        def query(self, _sql, parameters=None):
            self.query_count += 1
            if self.query_count == 1:
                return Result(["timestamp", "requests", "errors"], [(datetime(2026, 1, 1, tzinfo=timezone.utc), 5, 2)])
            if self.query_count == 2:
                return Result(["s2", "s3", "s4", "s5", "total", "unique_ip_count"], [(3, 0, 1, 1, 5, 2)])
            if self.query_count == 3:
                return Result(["path", "requests"], [("/wp-login.php", 3)])
            if self.query_count == 4:
                return Result(["src_ip", "requests"], [("::ffff:198.51.100.4", 4), ("::ffff:203.0.113.8", 1)])
            return Result(["src_ip", "requests"], [("::ffff:198.51.100.4", 4), ("::ffff:203.0.113.8", 1)])

        def close(self):
            self.closed = True

    client = Client()
    monkeypatch.setattr(clickhouse, "connect", lambda: client)
    monkeypatch.setattr(
        "app.db.postgres.countries_for_ips",
        lambda ips: {
            "198.51.100.4": {"country_code": "SG", "country": "Singapore"},
            "203.0.113.8": {"country_code": "VN", "country": "Viet Nam"},
        },
    )

    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    result = clickhouse.traffic(now, now, 60)

    assert result["total_requests"] == 5
    assert result["error_requests"] == 2
    assert result["unique_ips"] == 2
    assert result["unique_countries"] == 2
    assert result["top_ips"][0] == {"ip": "198.51.100.4", "requests": 4}
    assert {row["country_code"] for row in result["top_countries"]} == {"SG", "VN"}
    assert len(result["series"]) == 1
    assert client.query_count == 5
    assert client.closed


def test_raw_traffic_queries_preserve_exact_custom_window_and_path(monkeypatch):
    from datetime import datetime, timedelta, timezone
    from app.db import clickhouse

    start = datetime(2026, 9, 1, 10, 0, 30, tzinfo=timezone.utc)
    end = datetime(2026, 9, 1, 10, 1, 30, tzinfo=timezone.utc)
    path = "/unicode/đường-dẫn?a=1&b=2"
    events = [
        {"event_time": start - timedelta(seconds=1), "path": path, "src_ip": "::ffff:203.0.113.8", "status": 500},
        {"event_time": start + timedelta(seconds=1), "path": path, "src_ip": "::ffff:203.0.113.7", "status": 200},
        {"event_time": end - timedelta(seconds=1), "path": path, "src_ip": "::ffff:203.0.113.7", "status": 404},
        {"event_time": end + timedelta(seconds=1), "path": path, "src_ip": "::ffff:203.0.113.8", "status": 500},
    ]

    class Result:
        def __init__(self, names, rows):
            self.column_names, self.result_rows = names, rows

    class Client:
        def __init__(self):
            self.queries = []

        def query(self, sql, parameters=None):
            self.queries.append((sql, parameters))
            matched = [
                event for event in events
                if parameters["start"] <= event["event_time"] <= parameters["end"]
                and event["path"] == parameters.get("filter_value")
            ]
            if "unique_ip_count" in sql:
                statuses = [event["status"] for event in matched]
                return Result(
                    ["s2", "s3", "s4", "s5", "total", "unique_ip_count"],
                    [(sum(200 <= status <= 299 for status in statuses),
                      sum(300 <= status <= 399 for status in statuses),
                      sum(400 <= status <= 499 for status in statuses),
                      sum(status >= 500 for status in statuses), len(matched),
                      len({event["src_ip"] for event in matched}))],
                )
            if "GROUP BY timestamp" in sql:
                buckets = {}
                for event in matched:
                    bucket = event["event_time"].replace(second=0, microsecond=0)
                    buckets[bucket] = buckets.get(bucket, 0) + 1
                return Result(["timestamp", "requests", "errors"], [(key, count, 0) for key, count in buckets.items()])
            if "GROUP BY path" in sql:
                return Result(["path", "requests"], [(path, len(matched))] if matched else [])
            if "GROUP BY src_ip" in sql:
                counts = {}
                for event in matched:
                    counts[event["src_ip"]] = counts.get(event["src_ip"], 0) + 1
                rows = [(ip, count) for ip, count in counts.items()]
                if "LIMIT 8" in sql:
                    rows.sort(key=lambda item: (-item[1], item[0]))
                    rows = rows[:8]
                return Result(["src_ip", "requests"], rows)
            raise AssertionError(f"Unexpected query: {sql}")

        def close(self):
            pass

    client = Client()
    monkeypatch.setattr(clickhouse, "connect", lambda: client)
    monkeypatch.setattr("app.db.postgres.countries_for_ips", lambda _ips: {"203.0.113.7": {"country_code": "VN", "country": "Viet Nam"}})
    result = clickhouse.traffic(start, end, 60, filter_type="path", filter_value=path)

    assert result["_cohort_ips"] == ["203.0.113.7"]
    assert result["total_requests"] == 2
    assert result["unique_ips"] == 1
    assert result["top_ips"] == [{"ip": "203.0.113.7", "requests": 2}]
    assert result["top_paths"] == [{"path": path, "requests": 2, "ips": []}]
    assert len(client.queries) == 5
    for sql, params in client.queries:
        assert "event_time >= {start:DateTime64(3)}" in sql
        assert "event_time <= {end:DateTime64(3)}" in sql
        assert params["start"] == start
        assert params["end"] == end
        assert params["filter_value"] == path


def test_clickhouse_ip_display_and_filter_keep_same_logical_address():
    from app.db.clickhouse import _display_ip, _traffic_filter
    from datetime import datetime, timezone
    import ipaddress

    now = datetime(2026, 9, 1, tzinfo=timezone.utc)
    for stored, expected in (
        ("198.51.100.8", "198.51.100.8"),
        ("2001:db8::8", "2001:db8::8"),
        ("::ffff:198.51.100.8", "198.51.100.8"),
    ):
        displayed = _display_ip(stored)
        _, params = _traffic_filter(now, now, "live", "ip", displayed, False, None)
        assert displayed == expected
        bound_address = ipaddress.ip_address(params["filter_value"])
        assert (bound_address.ipv4_mapped or bound_address) == ipaddress.ip_address(expected)


def test_traffic_api_pairs_classification_with_clickhouse_cohort_and_hides_internal_ips(monkeypatch):
    from datetime import datetime, timezone

    exact_cohort = ["203.0.113.20", "2001:db8::20"]

    class Repository:
        def classification_summary_for_ips(self, ips):
            assert ips == exact_cohort
            return {"total_ips": 2, "classification": {"critical": 1, "medium": 0, "low": 0, "good": 0, "unknown": 1}}

        def risk_traffic_series(self, *_args, **_kwargs):
            return []

    monkeypatch.setattr(traffic.clickhouse_store, "traffic", lambda *_args, **_kwargs: {
        "total_requests": 2, "_cohort_ips": exact_cohort,
    })
    monkeypatch.setattr(traffic, "StateRepository", Repository)

    result = traffic._traffic(
        datetime(2026, 9, 1, 10, 0, 30, tzinfo=timezone.utc),
        datetime(2026, 9, 1, 10, 1, 30, tzinfo=timezone.utc),
        60, "custom", "custom window", "stream", "path", "/foo?a=1&b=2", True,
    )

    assert result["classification_summary"]["total_ips"] == 2
    assert result["classification_summary"]["classification"]["unknown"] == 1
    assert result["filter"] == {"type": "path", "value": "/foo?a=1&b=2", "exclude": True}
    assert "_cohort_ips" not in result


def test_empty_ip_path_and_exclude_cohorts_never_fall_back_to_unfiltered_summary(monkeypatch):
    from datetime import datetime, timezone

    class Repository:
        def classification_summary_for_ips(self, ips):
            assert ips == []
            return {"total_ips": 0, "classification": {"critical": 0, "medium": 0, "low": 0, "good": 0, "unknown": 0}}

        def risk_traffic_series(self, *_args, **_kwargs):
            return []

    monkeypatch.setattr(traffic.clickhouse_store, "traffic", lambda *_args, **_kwargs: {
        "total_requests": 0, "unique_ips": 0, "_cohort_ips": [],
        "top_ips": [], "top_paths": [],
    })
    monkeypatch.setattr(traffic, "StateRepository", Repository)
    now = datetime(2026, 9, 1, tzinfo=timezone.utc)

    for filter_type, filter_value, exclude in (
        ("ip", "192.0.2.99", False),
        ("path", "/not-seen", False),
        ("path", "/all-matching-removed", True),
    ):
        result = traffic._traffic(now, now, 60, "1h", "last 1 hour", "stream", filter_type, filter_value, exclude)

        assert result["total_requests"] == 0
        assert result["unique_ips"] == 0
        assert result["top_ips"] == []
        assert result["top_paths"] == []
        assert result["classification_summary"]["total_ips"] == 0
