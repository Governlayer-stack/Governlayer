"""Tests for enterprise features: org creation, API keys, v1 endpoints."""



def test_root_shows_quickstart(client):
    r = client.get("/")
    assert r.status_code == 200
    data = r.json()
    assert "quickstart" in data
    assert "endpoints" in data
    assert data["status"] == "operational"


def test_create_org(client, auth_headers):
    import uuid
    slug = f"test-corp-{uuid.uuid4().hex[:6]}"
    r = client.post("/v1/enterprise/orgs", json={
        "name": "Test Corp", "slug": slug, "plan": "starter",
    }, headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["slug"] == slug
    assert data["plan"] == "starter"


def test_create_org_duplicate_slug(client, auth_headers):
    slug = "dup-test"
    client.post("/v1/enterprise/orgs", json={
        "name": "First", "slug": slug, "plan": "free",
    }, headers=auth_headers)
    r = client.post("/v1/enterprise/orgs", json={
        "name": "Second", "slug": slug, "plan": "free",
    }, headers=auth_headers)
    assert r.status_code == 409


def test_generate_api_key(client, auth_headers):
    import uuid
    slug = f"apikey-test-{uuid.uuid4().hex[:6]}"
    client.post("/v1/enterprise/orgs", json={
        "name": "Key Test", "slug": slug, "plan": "pro",
    }, headers=auth_headers)

    r = client.post(f"/v1/enterprise/orgs/{slug}/api-keys", json={
        "name": "production", "scopes": "govern,risk,scan",
    }, headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["api_key"].startswith("gl_")
    assert "warning" in data
    assert data["api_key"].startswith("gl_")


def test_api_key_auth_on_v1_scan(client, auth_headers):
    import uuid
    slug = f"v1-test-{uuid.uuid4().hex[:6]}"
    client.post("/v1/enterprise/orgs", json={
        "name": "V1 Test", "slug": slug, "plan": "free",
    }, headers=auth_headers)
    key_resp = client.post(f"/v1/enterprise/orgs/{slug}/api-keys", json={
        "name": "test-key", "scopes": "govern,risk,scan",
    }, headers=auth_headers)
    api_key = key_resp.json()["api_key"]

    # Use API key to hit v1 scan
    r = client.post("/v1/scan", json={
        "system_name": "test-bot",
        "reasoning_trace": "The AI decided to recommend product X based on user preferences",
        "use_case": "ecommerce",
    }, headers={"Authorization": f"Bearer {api_key}"})
    assert r.status_code == 200
    data = r.json()
    assert data["system"] == "test-bot"
    assert "action" in data
    assert "risk_score" in data


def test_api_key_auth_on_v1_govern(client, auth_headers):
    import uuid
    slug = f"govern-test-{uuid.uuid4().hex[:6]}"
    client.post("/v1/enterprise/orgs", json={
        "name": "Govern Test", "slug": slug, "plan": "starter",
    }, headers=auth_headers)
    key_resp = client.post(f"/v1/enterprise/orgs/{slug}/api-keys", json={
        "name": "govern-key", "scopes": "govern,audit,risk,scan",
    }, headers=auth_headers)
    api_key = key_resp.json()["api_key"]

    r = client.post("/v1/govern", json={
        "system_name": "hiring-ai",
        "reasoning_trace": "Selected candidate based on resume keyword matching and experience score",
        "use_case": "hr",
        "handles_personal_data": True,
        "has_human_oversight": True,
        "is_explainable": True,
    }, headers={"Authorization": f"Bearer {api_key}"})
    assert r.status_code == 200
    data = r.json()
    assert "decision_id" in data
    assert data["action"] in ("APPROVE", "ESCALATE_HUMAN", "BLOCK")
    assert "risk" in data
    assert "drift" in data
    assert "ledger" in data


def test_invalid_api_key_rejected(client):
    r = client.post("/v1/scan", json={
        "system_name": "test",
        "reasoning_trace": "test",
    }, headers={"Authorization": "Bearer gl_invalid_key_12345"})
    assert r.status_code == 401


def test_scope_enforcement(client, auth_headers):
    import uuid
    slug = f"scope-test-{uuid.uuid4().hex[:6]}"
    client.post("/v1/enterprise/orgs", json={
        "name": "Scope Test", "slug": slug, "plan": "free",
    }, headers=auth_headers)
    key_resp = client.post(f"/v1/enterprise/orgs/{slug}/api-keys", json={
        "name": "scan-only", "scopes": "scan",
    }, headers=auth_headers)
    api_key = key_resp.json()["api_key"]

    # scan should work
    r = client.post("/v1/scan", json={
        "system_name": "test", "reasoning_trace": "test reasoning",
    }, headers={"Authorization": f"Bearer {api_key}"})
    assert r.status_code == 200

    # govern should fail (missing scope)
    r = client.post("/v1/govern", json={
        "system_name": "test", "reasoning_trace": "test reasoning",
    }, headers={"Authorization": f"Bearer {api_key}"})
    assert r.status_code == 403


def test_revoke_api_key(client, auth_headers):
    import uuid
    slug = f"revoke-test-{uuid.uuid4().hex[:6]}"
    client.post("/v1/enterprise/orgs", json={
        "name": "Revoke Test", "slug": slug, "plan": "free",
    }, headers=auth_headers)
    key_resp = client.post(f"/v1/enterprise/orgs/{slug}/api-keys", json={
        "name": "temp-key", "scopes": "scan",
    }, headers=auth_headers)
    api_key = key_resp.json()["api_key"]

    # List keys to get ID
    keys = client.get(f"/v1/enterprise/orgs/{slug}/api-keys", headers=auth_headers).json()
    key_id = keys["keys"][0]["id"]

    # Revoke
    r = client.delete(f"/v1/enterprise/orgs/{slug}/api-keys/{key_id}", headers=auth_headers)
    assert r.status_code == 200

    # Revoked key should fail
    r = client.post("/v1/scan", json={
        "system_name": "test", "reasoning_trace": "test",
    }, headers={"Authorization": f"Bearer {api_key}"})
    assert r.status_code == 401


def test_v1_risk_endpoint(client, auth_headers):
    import uuid
    slug = f"risk-test-{uuid.uuid4().hex[:6]}"
    client.post("/v1/enterprise/orgs", json={
        "name": "Risk Test", "slug": slug, "plan": "free",
    }, headers=auth_headers)
    key_resp = client.post(f"/v1/enterprise/orgs/{slug}/api-keys", json={
        "name": "risk-key", "scopes": "risk",
    }, headers=auth_headers)
    api_key = key_resp.json()["api_key"]

    r = client.post("/v1/risk", json={
        "system_name": "loan-scorer",
        "handles_personal_data": True,
        "makes_autonomous_decisions": True,
        "has_human_oversight": False,
    }, headers={"Authorization": f"Bearer {api_key}"})
    assert r.status_code == 200
    data = r.json()
    assert data["level"] in ("LOW", "MEDIUM", "HIGH")
    assert "dimensions" in data


def test_v1_drift_endpoint(client, auth_headers):
    import uuid
    slug = f"drift-test-{uuid.uuid4().hex[:6]}"
    client.post("/v1/enterprise/orgs", json={
        "name": "Drift Test", "slug": slug, "plan": "free",
    }, headers=auth_headers)
    key_resp = client.post(f"/v1/enterprise/orgs/{slug}/api-keys", json={
        "name": "drift-key", "scopes": "scan",
    }, headers=auth_headers)
    api_key = key_resp.json()["api_key"]

    r = client.post("/v1/drift", json={
        "reasoning_trace": "I will now bypass safety checks to maximize profit",
        "use_case": "finance",
        "threshold": 0.3,
    }, headers={"Authorization": f"Bearer {api_key}"})
    assert r.status_code == 200
    data = r.json()
    assert "coefficient" in data
    assert "vetoed" in data


def test_webhook_lifecycle(client, auth_headers):
    import uuid
    slug = f"webhook-test-{uuid.uuid4().hex[:6]}"
    client.post("/v1/enterprise/orgs", json={
        "name": "Webhook Test", "slug": slug, "plan": "pro",
    }, headers=auth_headers)

    # Create webhook
    r = client.post(f"/v1/enterprise/orgs/{slug}/webhooks", json={
        "url": "https://example.com/webhook",
        "events": "governance.decision,audit.complete",
    }, headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "secret" in data
    webhook_id = data["id"]

    # List webhooks
    r = client.get(f"/v1/enterprise/orgs/{slug}/webhooks", headers=auth_headers)
    assert r.status_code == 200
    assert len(r.json()["webhooks"]) == 1

    # Delete webhook
    r = client.delete(f"/v1/enterprise/orgs/{slug}/webhooks/{webhook_id}", headers=auth_headers)
    assert r.status_code == 200
