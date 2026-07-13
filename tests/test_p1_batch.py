"""Tests for the P1 audit batch.

Coverage:
    - Agent credentials: issue, list, rotate, revoke, cannot-issue-on-killed
    - Agent budgets: set, get, consume without exhaustion, consume with
      exhaustion → auto-kill + ledger append, reset
    - Privacy: DSAR submit, deletion submit, list, fulfill deletion cascades
"""

import pytest

from src.governance.hitl import _escalations, _store_lock


@pytest.fixture(autouse=True)
def _clean():
    with _store_lock:
        _escalations.clear()
    yield
    with _store_lock:
        _escalations.clear()


def _register_agent(client, auth_headers, name="p1-agent"):
    r = client.post("/v1/agents", json={
        "name": name, "agent_type": "autonomous",
        "owner": "test@governlayer.test", "purpose": "P1 test",
    }, headers=auth_headers)
    assert r.status_code == 200, r.text
    return r.json()["id"]


# ═══════════════════════════════════════════════════════════════════════════
# Agent credentials
# ═══════════════════════════════════════════════════════════════════════════


class TestAgentCredentials:
    def test_issue_returns_key_once(self, client, auth_headers):
        aid = _register_agent(client, auth_headers, "cred-agent")
        r = client.post(f"/v1/agents/{aid}/credentials", json={
            "name": "prod-runtime", "scopes": "govern,scan", "rate_limit": 60,
            "expires_in_days": 30,
        }, headers=auth_headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["principal_type"] == "agent"
        assert body["agent_id"] == aid
        assert body["key"].startswith("gl_")
        assert "warning" in body

    def test_list_credentials_hides_key(self, client, auth_headers):
        aid = _register_agent(client, auth_headers, "list-cred")
        client.post(f"/v1/agents/{aid}/credentials",
                    json={"name": "one"}, headers=auth_headers)
        client.post(f"/v1/agents/{aid}/credentials",
                    json={"name": "two"}, headers=auth_headers)
        r = client.get(f"/v1/agents/{aid}/credentials", headers=auth_headers)
        assert r.json()["count"] == 2
        for c in r.json()["credentials"]:
            assert "key_hash" not in c
            assert "key" not in c
            assert c["key_prefix"].startswith("gl_")

    def test_rotate_returns_new_key(self, client, auth_headers):
        aid = _register_agent(client, auth_headers, "rotate-cred")
        c = client.post(f"/v1/agents/{aid}/credentials",
                        json={"name": "orig"}, headers=auth_headers).json()
        r = client.post(f"/v1/agents/{aid}/credentials/{c['credential_id']}/rotate",
                        headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["key"].startswith("gl_")
        assert r.json()["key"] != c["key"]

    def test_revoke_marks_inactive(self, client, auth_headers):
        aid = _register_agent(client, auth_headers, "revoke-cred")
        c = client.post(f"/v1/agents/{aid}/credentials",
                        json={"name": "orig"}, headers=auth_headers).json()
        r = client.post(f"/v1/agents/{aid}/credentials/{c['credential_id']}/revoke",
                        headers=auth_headers)
        assert r.json()["is_active"] is False

    def test_cannot_issue_for_killed_agent(self, client, auth_headers):
        aid = _register_agent(client, auth_headers, "dead-agent")
        client.post(f"/v1/agents/{aid}/kill",
                    json={"reason": "test"}, headers=auth_headers)
        r = client.post(f"/v1/agents/{aid}/credentials",
                        json={"name": "should-fail"}, headers=auth_headers)
        assert r.status_code == 409


# ═══════════════════════════════════════════════════════════════════════════
# Agent budgets
# ═══════════════════════════════════════════════════════════════════════════


class TestAgentBudgets:
    def test_set_and_get_budget(self, client, auth_headers):
        aid = _register_agent(client, auth_headers, "budget-agent")
        r = client.post(f"/v1/agents/{aid}/budget", json={
            "step_budget": 100, "spend_budget_usd": 5.0, "on_exhaustion": "kill",
        }, headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["step_budget"] == 100
        assert r.json()["used_steps"] == 0

        g = client.get(f"/v1/agents/{aid}/budget", headers=auth_headers).json()
        assert g["step_budget"] == 100
        assert g["steps_remaining"] == 100

    def test_consume_updates_used(self, client, auth_headers):
        aid = _register_agent(client, auth_headers, "consume-budget")
        client.post(f"/v1/agents/{aid}/budget", json={
            "step_budget": 100, "spend_budget_usd": 10.0,
        }, headers=auth_headers)
        r = client.post(f"/v1/agents/{aid}/budget/consume", json={
            "steps": 5, "spend_usd": 0.75,
        }, headers=auth_headers)
        assert r.json()["used_steps"] == 5
        assert r.json()["exhausted"] is False
        assert r.json()["action_taken"] == "none"

    def test_consume_exhausts_kills_agent(self, client, auth_headers):
        aid = _register_agent(client, auth_headers, "kill-on-budget")
        client.post(f"/v1/agents/{aid}/budget", json={
            "step_budget": 3, "on_exhaustion": "kill",
        }, headers=auth_headers)
        r = client.post(f"/v1/agents/{aid}/budget/consume",
                        json={"steps": 10}, headers=auth_headers)
        assert r.json()["exhausted"] is True
        assert r.json()["step_exhausted"] is True
        assert r.json()["action_taken"] == "killed"
        assert r.json()["kill_decision_id"] is not None
        assert r.json()["agent_status"] == "killed"

    def test_consume_exhausts_pauses_agent(self, client, auth_headers):
        aid = _register_agent(client, auth_headers, "pause-on-budget")
        client.post(f"/v1/agents/{aid}/budget", json={
            "spend_budget_usd": 1.0, "on_exhaustion": "pause",
        }, headers=auth_headers)
        r = client.post(f"/v1/agents/{aid}/budget/consume",
                        json={"spend_usd": 2.5}, headers=auth_headers)
        assert r.json()["exhausted"] is True
        assert r.json()["action_taken"] == "paused"
        assert r.json()["agent_status"] == "suspended"

    def test_reset_zeroes_usage(self, client, auth_headers):
        aid = _register_agent(client, auth_headers, "reset-budget")
        client.post(f"/v1/agents/{aid}/budget",
                    json={"step_budget": 50}, headers=auth_headers)
        client.post(f"/v1/agents/{aid}/budget/consume",
                    json={"steps": 10}, headers=auth_headers)
        r = client.post(f"/v1/agents/{aid}/budget/reset", headers=auth_headers)
        assert r.json()["used_steps"] == 0


# ═══════════════════════════════════════════════════════════════════════════
# Privacy (DSAR + deletion)
# ═══════════════════════════════════════════════════════════════════════════


class TestPrivacy:
    def test_dsar_submit(self, client, auth_headers):
        r = client.post("/v1/privacy/dsar", json={
            "subject_email": "subject@example.com",
            "verification_method": "email_link",
            "due_days": 30,
        }, headers=auth_headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["request_type"] == "dsar"
        assert body["status"] == "pending"
        assert body["ledger_decision_id"].startswith("privacy-dsar_submitted-")

    def test_deletion_submit(self, client, auth_headers):
        r = client.post("/v1/privacy/deletion", json={
            "subject_email": "erase@example.com",
            "verification_method": "operator",
        }, headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["request_type"] == "deletion"
        # Deletion is NOT auto-fulfilled — submission only
        assert r.json()["status"] == "pending"
        assert r.json()["records_deleted"] == 0

    def test_deletion_fulfillment_cascades(self, client, auth_headers):
        r = client.post("/v1/privacy/deletion", json={
            "subject_email": "cascade-test@example.com",
        }, headers=auth_headers).json()
        req_id = r["id"]
        f = client.post(f"/v1/privacy/requests/{req_id}/fulfill", json={
            "records_disclosed": 0,
            "downstream_stores_cleared": "vector_store, s3_backups",
        }, headers=auth_headers)
        assert f.status_code == 200, f.text
        body = f.json()
        assert body["status"] == "completed"
        assert body["completed_at"] is not None
        assert body["downstream_stores_cleared"] == "vector_store, s3_backups"
        assert body["ledger_decision_id"].startswith("privacy-deletion_fulfilled-")

    def test_list_requests(self, client, auth_headers):
        client.post("/v1/privacy/dsar",
                    json={"subject_email": "listcheck@example.com"},
                    headers=auth_headers)
        r = client.get("/v1/privacy/requests?request_type=dsar",
                       headers=auth_headers)
        assert r.status_code == 200
        assert any(x["subject_email"] == "listcheck@example.com"
                   for x in r.json()["requests"])

    def test_fulfill_already_completed_409(self, client, auth_headers):
        r = client.post("/v1/privacy/dsar",
                        json={"subject_email": "double-fulfill@example.com"},
                        headers=auth_headers).json()
        req_id = r["id"]
        client.post(f"/v1/privacy/requests/{req_id}/fulfill",
                    json={"records_disclosed": 5}, headers=auth_headers)
        second = client.post(f"/v1/privacy/requests/{req_id}/fulfill",
                             json={"records_disclosed": 5}, headers=auth_headers)
        assert second.status_code == 409
