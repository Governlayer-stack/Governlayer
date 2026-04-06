"""Tests for Agent Registry API — /v1/agents CRUD + governance + shadow AI."""

import uuid


def _unique_name():
    return f"test-agent-{uuid.uuid4().hex[:8]}"


def test_register_agent(client, auth_headers):
    name = _unique_name()
    r = client.post("/v1/agents", json={
        "name": name,
        "agent_type": "chatbot",
        "description": "Customer support chatbot",
        "owner": "cx-team@company.com",
        "team": "Customer Experience",
        "purpose": "Handle tier-1 support tickets",
        "tools": ["ticket_lookup", "knowledge_base"],
        "autonomy_level": 2,
        "model_provider": "OpenAI",
        "model_name": "gpt-4o",
        "risk_tier": "medium",
        "tags": ["support", "chatbot"],
    }, headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["name"] == name
    assert data["agent_type"] == "chatbot"
    assert data["status"] == "under_review"
    assert data["is_shadow"] is False
    assert data["discovery_source"] == "manual"
    assert data["tools"] == ["ticket_lookup", "knowledge_base"]
    assert "id" in data


def test_register_agent_minimal(client, auth_headers):
    name = _unique_name()
    r = client.post("/v1/agents", json={
        "name": name,
    }, headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["name"] == name
    assert data["agent_type"] == "autonomous"
    assert data["autonomy_level"] == 1


def test_register_agent_requires_auth(client):
    r = client.post("/v1/agents", json={
        "name": "unauthorized-agent",
    })
    assert r.status_code in (401, 403)


def test_list_agents(client, auth_headers):
    for _ in range(2):
        client.post("/v1/agents", json={
            "name": _unique_name(),
        }, headers=auth_headers)

    r = client.get("/v1/agents")
    assert r.status_code == 200
    data = r.json()
    assert "items" in data
    assert "pagination" in data
    assert data["pagination"]["total"] >= 2
    assert "page" in data["pagination"]
    assert "per_page" in data["pagination"]
    assert "pages" in data["pagination"]
    assert "approved" in data
    assert "shadow_detected" in data


def test_list_agents_pagination(client, auth_headers):
    for _ in range(3):
        client.post("/v1/agents", json={
            "name": _unique_name(),
        }, headers=auth_headers)

    r = client.get("/v1/agents?page=1&per_page=2")
    assert r.status_code == 200
    data = r.json()
    assert data["pagination"]["page"] == 1
    assert data["pagination"]["per_page"] == 2
    assert len(data["items"]) <= 2


def test_list_agents_filter_by_team(client, auth_headers):
    team_name = f"team-{uuid.uuid4().hex[:6]}"
    client.post("/v1/agents", json={
        "name": _unique_name(),
        "team": team_name,
    }, headers=auth_headers)

    r = client.get(f"/v1/agents?team={team_name}")
    assert r.status_code == 200
    data = r.json()
    assert data["pagination"]["total"] >= 1
    for a in data["items"]:
        assert a["team"] == team_name


def test_get_agent_by_id(client, auth_headers):
    name = _unique_name()
    create_resp = client.post("/v1/agents", json={
        "name": name,
        "agent_type": "tool_agent",
        "description": "Code review assistant",
        "owner": "devtools@company.com",
        "team": "Engineering",
        "purpose": "Automated PR review",
        "model_provider": "Anthropic",
        "model_name": "claude-sonnet",
    }, headers=auth_headers)
    agent_id = create_resp.json()["id"]

    r = client.get(f"/v1/agents/{agent_id}")
    assert r.status_code == 200
    data = r.json()
    assert data["id"] == agent_id
    assert data["name"] == name
    assert data["agent_type"] == "tool_agent"
    assert data["description"] == "Code review assistant"
    assert data["model_provider"] == "Anthropic"


def test_get_agent_not_found(client):
    r = client.get("/v1/agents/999999")
    assert r.status_code == 404


def test_agent_governance_approve(client, auth_headers):
    create_resp = client.post("/v1/agents", json={
        "name": _unique_name(),
    }, headers=auth_headers)
    agent_id = create_resp.json()["id"]

    r = client.post(f"/v1/agents/{agent_id}/governance", json={
        "action": "approve",
        "reason": "Passed security review",
    }, headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "approved"
    assert data["governance_status"] == "compliant"


def test_agent_governance_reject(client, auth_headers):
    create_resp = client.post("/v1/agents", json={
        "name": _unique_name(),
    }, headers=auth_headers)
    agent_id = create_resp.json()["id"]

    r = client.post(f"/v1/agents/{agent_id}/governance", json={
        "action": "reject",
        "reason": "Failed bias testing",
    }, headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "rejected"
    assert data["governance_status"] == "non_compliant"


def test_agent_governance_suspend(client, auth_headers):
    create_resp = client.post("/v1/agents", json={
        "name": _unique_name(),
    }, headers=auth_headers)
    agent_id = create_resp.json()["id"]

    r = client.post(f"/v1/agents/{agent_id}/governance", json={
        "action": "suspend",
    }, headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["status"] == "suspended"
    assert r.json()["governance_status"] == "suspended"


def test_agent_governance_invalid_action(client, auth_headers):
    create_resp = client.post("/v1/agents", json={
        "name": _unique_name(),
    }, headers=auth_headers)
    agent_id = create_resp.json()["id"]

    r = client.post(f"/v1/agents/{agent_id}/governance", json={
        "action": "invalid_action",
    }, headers=auth_headers)
    assert r.status_code == 400


def test_agent_governance_not_found(client, auth_headers):
    r = client.post("/v1/agents/999999/governance", json={
        "action": "approve",
    }, headers=auth_headers)
    assert r.status_code == 404


def test_agent_governance_requires_auth(client, auth_headers):
    create_resp = client.post("/v1/agents", json={
        "name": _unique_name(),
    }, headers=auth_headers)
    agent_id = create_resp.json()["id"]

    r = client.post(f"/v1/agents/{agent_id}/governance", json={
        "action": "approve",
    })
    assert r.status_code in (401, 403)


def test_shadow_ai_scan(client, auth_headers):
    r = client.post("/v1/agents/discovery/scan", json={
        "scan_type": "api_patterns",
        "targets": [
            "https://api.openai.com/v1/chat/completions",
            "https://api.anthropic.com/v1/messages",
            "https://internal.company.com/api",
        ],
    }, headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["scan_type"] == "api_patterns"
    assert data["targets_scanned"] == 3
    assert "total_detections" in data
    assert "unregistered_ai" in data
    assert "risk_level" in data
    assert "detections" in data
    assert "known_patterns" in data
    assert data["known_patterns"] > 0


def test_shadow_ai_scan_no_targets(client, auth_headers):
    r = client.post("/v1/agents/discovery/scan", json={
        "scan_type": "api_patterns",
        "targets": [],
    }, headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["targets_scanned"] == 0
    assert data["total_detections"] == 0
    assert data["risk_level"] == "safe"


def test_shadow_ai_scan_requires_auth(client):
    r = client.post("/v1/agents/discovery/scan", json={
        "scan_type": "api_patterns",
        "targets": ["https://api.openai.com/v1/chat"],
    })
    assert r.status_code in (401, 403)
