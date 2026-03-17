"""Tests for API Usage Analytics endpoints."""


def test_usage_summary(client):
    r = client.get("/v1/analytics/usage/summary")
    assert r.status_code == 200
    data = r.json()
    assert "total_requests" in data
    assert "error_rate" in data
    assert "average_latency_ms" in data
    assert "active_api_keys" in data
    assert "requests_per_day" in data
    assert data["period_days"] == 30


def test_usage_summary_custom_days(client):
    r = client.get("/v1/analytics/usage/summary?days=7")
    assert r.status_code == 200
    assert r.json()["period_days"] == 7


def test_usage_trends(client):
    r = client.get("/v1/analytics/usage/trends")
    assert r.status_code == 200
    data = r.json()
    assert "data_points" in data
    assert data["granularity"] == "day"
    assert isinstance(data["data_points"], list)


def test_usage_trends_hourly(client):
    r = client.get("/v1/analytics/usage/trends?granularity=hour&days=1")
    assert r.status_code == 200
    assert r.json()["granularity"] == "hour"


def test_top_endpoints(client):
    r = client.get("/v1/analytics/usage/top-endpoints")
    assert r.status_code == 200
    data = r.json()
    assert "endpoints" in data
    assert isinstance(data["endpoints"], list)


def test_latency_stats(client):
    r = client.get("/v1/analytics/usage/latency")
    assert r.status_code == 200
    data = r.json()
    assert "avg_ms" in data
    assert "p50_ms" in data
    assert "p95_ms" in data
    assert "p99_ms" in data


def test_error_breakdown(client):
    r = client.get("/v1/analytics/usage/errors")
    assert r.status_code == 200
    data = r.json()
    assert "total_errors" in data
    assert "error_rate" in data
    assert "by_status_code" in data


def test_governance_analytics(client):
    r = client.get("/v1/analytics/usage/governance")
    assert r.status_code == 200
    data = r.json()
    assert "total_decisions" in data
    assert "by_action" in data
    assert isinstance(data["by_action"], list)
