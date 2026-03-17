"""Tests for core API endpoints — root, health, frameworks, auth, dashboard."""

import uuid


def test_root_returns_json(client):
    r = client.get("/")
    assert r.status_code == 200
    data = r.json()
    assert data["name"] == "GovernLayer"
    assert data["tagline"] == "The Governance Layer for Agentic AI"
    assert data["status"] == "operational"
    assert "quickstart" in data
    assert "endpoints" in data
    assert "version" in data
    assert "frameworks" in data


def test_health_endpoint(client):
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] in ("healthy", "degraded")
    assert "database" in data
    assert data["database"] in ("connected", "unavailable")
    assert "version" in data


def test_api_status(client):
    r = client.get("/api")
    assert r.status_code == 200
    data = r.json()
    assert data["name"] == "GovernLayer"
    assert data["tagline"] == "The Governance Layer for Agentic AI"
    assert data["status"] == "operational"
    assert "version" in data
    assert "frameworks" in data
    assert "docs" in data


def test_frameworks_list(client):
    r = client.get("/frameworks")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 27
    assert len(data["frameworks"]) == 27
    assert "NIST_AI_RMF" in data["frameworks"]
    assert "EU_AI_ACT" in data["frameworks"]
    assert "ISO_42001" in data["frameworks"]
    assert "GDPR" in data["frameworks"]
    assert "HIPAA" in data["frameworks"]


def test_register_and_login_flow(client):
    email = f"test-{uuid.uuid4().hex[:8]}@governlayer.test"
    password = "SecurePass123!"
    company = "TestCorp"

    # Register
    reg_resp = client.post("/auth/register", json={
        "email": email,
        "password": password,
        "company": company,
    })
    assert reg_resp.status_code == 200
    reg_data = reg_resp.json()
    assert "token" in reg_data
    assert reg_data["email"] == email
    assert "message" in reg_data

    # Login with same credentials
    login_resp = client.post("/auth/login", json={
        "email": email,
        "password": password,
    })
    assert login_resp.status_code == 200
    login_data = login_resp.json()
    assert "token" in login_data
    assert login_data["email"] == email

    # Token should work for authenticated endpoints
    token = login_data["token"]
    headers = {"Authorization": f"Bearer {token}"}
    govern_resp = client.post("/govern", json={
        "system_name": "auth-test-bot",
        "reasoning_trace": "Evaluating loan based on credit score and income",
        "use_case": "finance",
        "ai_decision": "approve",
    }, headers=headers)
    assert govern_resp.status_code == 200


def test_register_duplicate_email(client):
    email = f"dup-{uuid.uuid4().hex[:8]}@governlayer.test"
    client.post("/auth/register", json={
        "email": email,
        "password": "Pass12345",
        "company": "Corp",
    })
    r = client.post("/auth/register", json={
        "email": email,
        "password": "Pass45678",
        "company": "OtherCorp",
    })
    assert r.status_code == 400


def test_login_invalid_credentials(client):
    r = client.post("/auth/login", json={
        "email": "nonexistent@governlayer.test",
        "password": "WrongPassword",
    })
    assert r.status_code == 401


def test_dashboard_json(client):
    r = client.get("/v1/dashboard")
    assert r.status_code == 200
    data = r.json()
    assert "dashboard" in data
    dash = data["dashboard"]
    assert "generated_at" in dash
    assert "health" in dash
    assert "models" in dash
    assert "incidents" in dash
    assert "policies" in dash
    assert "quick_actions" in dash

    # Health section structure
    health = dash["health"]
    assert "score" in health
    assert "status" in health
    assert health["status"] in ("healthy", "warning", "degraded", "critical")
    assert 0 <= health["score"] <= 100

    # Models section
    models = dash["models"]
    assert "total" in models
    assert "by_lifecycle" in models
    assert "by_governance_status" in models

    # Incidents section
    incidents = dash["incidents"]
    assert "total" in incidents
    assert "open" in incidents
    assert "critical_open" in incidents
    assert "by_severity" in incidents

    # Policies section
    policies = dash["policies"]
    assert "active_policies" in policies
    assert "total_rules" in policies


def test_dashboard_html_fallback(client):
    """GET /dashboard returns either HTML or a fallback JSON message."""
    r = client.get("/dashboard")
    assert r.status_code == 200


def test_docs_endpoint(client):
    """OpenAPI docs should be served at /docs."""
    r = client.get("/docs")
    assert r.status_code == 200


def test_redoc_endpoint(client):
    """ReDoc docs should be served at /redoc."""
    r = client.get("/redoc")
    assert r.status_code == 200


def test_security_headers(client):
    """Verify security headers are set on responses."""
    r = client.get("/health")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert r.headers.get("X-XSS-Protection") == "1; mode=block"
    assert "strict-origin" in r.headers.get("Referrer-Policy", "")
    assert "max-age=" in r.headers.get("Strict-Transport-Security", "")
    assert "camera=()" in r.headers.get("Permissions-Policy", "")
