"""Tests for P0 fixes: /admin/infra-check + agent kill switch.

/admin/infra-check
    - Requires X-Admin-Key when ADMIN_KEY env var is set.
    - Returns 503 when ADMIN_KEY is not configured.
    - Returns structured report on success.

POST /v1/agents/{id}/kill
    - Transitions agent to KILLED regardless of prior state.
    - Writes hash-chained audit record.
    - Idempotent — killing an already-killed agent returns 200 with
      `already_killed: true`.
    - 404 for unknown agent.
"""

import pytest


@pytest.fixture
def admin_key_env(monkeypatch):
    monkeypatch.setenv("ADMIN_KEY", "test-admin-key-42")
    from src.config import get_settings
    get_settings.cache_clear()
    yield "test-admin-key-42"
    monkeypatch.delenv("ADMIN_KEY", raising=False)
    get_settings.cache_clear()


class TestAdminInfraCheck:
    def test_missing_admin_key_header_401(self, client, admin_key_env):
        r = client.get("/admin/infra-check")
        assert r.status_code == 401

    def test_wrong_admin_key_header_401(self, client, admin_key_env):
        r = client.get("/admin/infra-check", headers={"X-Admin-Key": "wrong"})
        assert r.status_code == 401

    def test_correct_admin_key_returns_report(self, client, admin_key_env):
        r = client.get("/admin/infra-check", headers={"X-Admin-Key": admin_key_env})
        assert r.status_code == 200, r.text
        body = r.json()
        assert "overall_verdict" in body
        assert "checks" in body
        check_names = {c["check"] for c in body["checks"]}
        assert check_names == {"postgres", "redis", "sentry", "llm_providers", "stripe", "cors"}

    def test_env_audit_lists_missing_vars(self, client, admin_key_env):
        r = client.get("/admin/env-audit", headers={"X-Admin-Key": admin_key_env})
        assert r.status_code == 200
        body = r.json()
        assert "missing" in body
        assert "fields" in body
        # SECRET_KEY is set (from conftest) so should not be in missing
        # ADMIN_KEY is set via fixture
        assert "ADMIN_KEY" not in body["missing"]

    def test_admin_key_unconfigured_returns_503(self, client, monkeypatch):
        monkeypatch.delenv("ADMIN_KEY", raising=False)
        from src.config import get_settings
        get_settings.cache_clear()
        r = client.get("/admin/infra-check", headers={"X-Admin-Key": "anything"})
        assert r.status_code == 503
        get_settings.cache_clear()


# ═══════════════════════════════════════════════════════════════════════════
# Agent kill switch
# ═══════════════════════════════════════════════════════════════════════════


class TestAgentKillSwitch:
    def _register_agent(self, client, auth_headers, name="test-agent"):
        r = client.post("/v1/agents", json={
            "name": name,
            "agent_type": "autonomous",
            "owner": "test@governlayer.test",
            "purpose": "kill-switch test",
        }, headers=auth_headers)
        assert r.status_code == 200, r.text
        return r.json()["id"]

    def test_kill_agent_transitions_to_killed(self, client, auth_headers):
        agent_id = self._register_agent(client, auth_headers, "kill-me")
        r = client.post(f"/v1/agents/{agent_id}/kill", json={
            "reason": "Runaway agent detected during red-team eval",
            "kill_source": "operator",
        }, headers=auth_headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "killed"
        assert body["already_killed"] is False
        assert body["kill_source"] == "operator"
        assert len(body["current_hash"]) == 64
        assert "SR_26_2" in body["frameworks_cited"]

    def test_kill_agent_is_idempotent(self, client, auth_headers):
        agent_id = self._register_agent(client, auth_headers, "kill-twice")
        client.post(f"/v1/agents/{agent_id}/kill",
                    json={"reason": "first kill"}, headers=auth_headers)
        r = client.post(f"/v1/agents/{agent_id}/kill",
                        json={"reason": "second kill"}, headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["already_killed"] is True
        # Still KILLED, not resurrected
        assert r.json()["status"] == "killed"

    def test_kill_unknown_agent_404(self, client, auth_headers):
        r = client.post("/v1/agents/999999/kill",
                        json={"reason": "no such agent"}, headers=auth_headers)
        assert r.status_code == 404

    def test_kill_requires_reason(self, client, auth_headers):
        agent_id = self._register_agent(client, auth_headers, "needs-reason")
        r = client.post(f"/v1/agents/{agent_id}/kill",
                        json={}, headers=auth_headers)
        assert r.status_code == 422  # missing required field

    def test_kill_ledgers_the_termination(self, client, auth_headers):
        agent_id = self._register_agent(client, auth_headers, "ledger-me")
        r = client.post(f"/v1/agents/{agent_id}/kill", json={
            "reason": "eval failure",
            "kill_source": "auto_guardrail",
        }, headers=auth_headers)
        decision_id = r.json()["decision_id"]
        assert decision_id.startswith("kill-")
        # The kill produced a hash-chained record — verify by fetching the ledger.
        # Walk pages until we find it (ledger orders ascending by id).
        found = None
        for page in range(1, 50):
            resp = client.get(f"/ledger?page={page}&per_page=100", headers=auth_headers).json()
            entries = resp.get("items", [])
            if not entries:
                break
            for e in entries:
                if e["decision_id"] == decision_id:
                    found = e
                    break
            if found or not resp["pagination"]["has_next"]:
                break
        assert found is not None, "kill decision_id not found in ledger"
        assert found["governance_action"] == "KILL_AGENT"
