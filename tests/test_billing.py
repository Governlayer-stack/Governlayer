"""Tests for billing and monthly quota enforcement."""

from unittest.mock import MagicMock, patch


def test_monthly_caps_defined():
    """Verify PLAN_MONTHLY_CAPS has correct values for all plans."""
    from src.middleware.rate_limit import PLAN_MONTHLY_CAPS

    assert PLAN_MONTHLY_CAPS["free"] == 500
    assert PLAN_MONTHLY_CAPS["starter"] == 10_000
    assert PLAN_MONTHLY_CAPS["pro"] == 100_000
    assert PLAN_MONTHLY_CAPS["enterprise"] is None  # unlimited


def test_billing_usage_endpoint(client, auth_headers):
    """Verify billing usage response includes monthly_cap and usage_percentage."""
    import uuid

    slug = f"billing-test-{uuid.uuid4().hex[:6]}"

    # Create org
    client.post("/v1/enterprise/orgs", json={
        "name": "Billing Test", "slug": slug, "plan": "starter",
    }, headers=auth_headers)

    # Get usage
    r = client.get(f"/billing/usage/{slug}", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()

    assert data["org"] == slug
    assert data["plan"] == "starter"
    assert "monthly_cap" in data
    assert data["monthly_cap"] == 10_000
    assert "usage_percentage" in data
    # With zero requests, usage_percentage should be 0
    assert data["usage_percentage"] == 0.0
    assert "total_requests" in data
    assert "plan_cost_usd" in data


def test_billing_usage_enterprise_unlimited(client, auth_headers):
    """Enterprise plan should have monthly_cap=None and usage_percentage=None."""
    import uuid

    slug = f"ent-billing-{uuid.uuid4().hex[:6]}"

    client.post("/v1/enterprise/orgs", json={
        "name": "Enterprise Billing", "slug": slug, "plan": "enterprise",
    }, headers=auth_headers)

    r = client.get(f"/billing/usage/{slug}", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()

    assert data["monthly_cap"] is None
    assert data["usage_percentage"] is None


def test_monthly_quota_check_allows_under_limit():
    """_check_monthly_quota returns allowed=True when under the cap."""
    from src.middleware.rate_limit import _check_monthly_quota, _monthly_cache, _monthly_cache_lock

    # Seed the cache directly to avoid DB dependency
    import time
    with _monthly_cache_lock:
        _monthly_cache["gl_testke"] = (10, 500, "free", time.time())

    allowed, used, limit = _check_monthly_quota("gl_testke")
    assert allowed is True
    assert used == 10
    assert limit == 500

    # Clean up
    with _monthly_cache_lock:
        _monthly_cache.pop("gl_testke", None)


def test_monthly_quota_check_blocks_over_limit():
    """_check_monthly_quota returns allowed=False when at or over the cap."""
    from src.middleware.rate_limit import _check_monthly_quota, _monthly_cache, _monthly_cache_lock

    import time
    with _monthly_cache_lock:
        _monthly_cache["gl_overlm"] = (500, 500, "free", time.time())

    allowed, used, limit = _check_monthly_quota("gl_overlm")
    assert allowed is False
    assert used == 500
    assert limit == 500

    # Clean up
    with _monthly_cache_lock:
        _monthly_cache.pop("gl_overlm", None)


def test_monthly_quota_check_unlimited_enterprise():
    """Enterprise plan (limit=None) should always be allowed."""
    from src.middleware.rate_limit import _check_monthly_quota, _monthly_cache, _monthly_cache_lock

    import time
    with _monthly_cache_lock:
        _monthly_cache["gl_entrpr"] = (999_999, None, "enterprise", time.time())

    allowed, used, limit = _check_monthly_quota("gl_entrpr")
    assert allowed is True
    assert limit is None

    # Clean up
    with _monthly_cache_lock:
        _monthly_cache.pop("gl_entrpr", None)
