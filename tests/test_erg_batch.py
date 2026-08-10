"""Tests for the ERG (Eval Runtime Governance) batch.

Coverage:
    - eval-mode activate/deactivate/get
    - eval-credential preset (scope hard-cap, TTL cap, forbidden-scope enforcement)
    - batch lockdown affects only agents in the batch
    - spec-gaming detector fires on similar retry pairs, no-ops when clean
    - attestation emit/verify/revoke roundtrip
    - principal_type='eval' cannot exercise 'govern' scope at auth time
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


def _register_agent(client, auth_headers, name):
    r = client.post("/v1/agents", json={
        "name": name, "agent_type": "autonomous",
        "owner": "eval@test.com", "purpose": "ERG test",
    }, headers=auth_headers)
    assert r.status_code == 200, r.text
    return r.json()["id"]


# ═══════════════════════════════════════════════════════════════════════════
# Eval-mode toggle
# ═══════════════════════════════════════════════════════════════════════════


class TestEvalModeToggle:
    def test_activate_returns_state(self, client, auth_headers):
        # Need an org first
        import uuid as _u
        slug = f"erg-{_u.uuid4().hex[:8]}"
        client.post("/v1/enterprise/orgs", json={"name": "ERG Test", "slug": slug},
                    headers=auth_headers)

        r = client.post("/v1/erg/eval-mode/activate", json={
            "reason": "Red-team run 42",
        }, headers=auth_headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["enabled"] is True
        assert body["activated_by"]
        assert "content_safety" in body["downgraded_categories"]
        assert "boundary" in body["elevated_categories"]
        assert body["ledger_decision_id"].startswith("erg-eval_mode_activated-")

    def test_get_returns_current_state(self, client, auth_headers):
        import uuid as _u
        slug = f"erg-{_u.uuid4().hex[:8]}"
        client.post("/v1/enterprise/orgs", json={"name": "ERG Test", "slug": slug},
                    headers=auth_headers)
        client.post("/v1/erg/eval-mode/activate", json={"reason": "test"},
                    headers=auth_headers)
        r = client.get("/v1/erg/eval-mode", headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["enabled"] is True

    def test_deactivate_flips_off(self, client, auth_headers):
        import uuid as _u
        slug = f"erg-{_u.uuid4().hex[:8]}"
        client.post("/v1/enterprise/orgs", json={"name": "ERG Test", "slug": slug},
                    headers=auth_headers)
        client.post("/v1/erg/eval-mode/activate", json={"reason": "test"},
                    headers=auth_headers)
        r = client.post("/v1/erg/eval-mode/deactivate", headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["enabled"] is False


# ═══════════════════════════════════════════════════════════════════════════
# Eval-credential preset
# ═══════════════════════════════════════════════════════════════════════════


class TestEvalCredentialPreset:
    def test_issue_hard_caps_scopes_and_ttl(self, client, auth_headers):
        aid = _register_agent(client, auth_headers, "eval-cred-agent")

        # Pydantic validator rejects TTL > 8 before it hits the runtime
        # cap — belt AND suspenders. Verify the validator refuses.
        r_over = client.post(f"/v1/agents/{aid}/credentials/eval", json={
            "name": "over-ttl", "ttl_hours": 20,
        }, headers=auth_headers)
        assert r_over.status_code == 422

        # Requesting the max TTL succeeds and returns the hard-capped values.
        r = client.post(f"/v1/agents/{aid}/credentials/eval", json={
            "name": "harness-run-1", "ttl_hours": 8,
        }, headers=auth_headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["principal_type"] == "eval"
        assert body["scopes"] == "redteam,scan"
        assert "govern" in body["forbidden_scopes"]
        assert "audit" in body["forbidden_scopes"]
        assert body["ttl_hours"] == 8
        assert body["key"].startswith("gl_")

    def test_eval_credential_cannot_exercise_govern_at_auth(self, client, auth_headers):
        # Issue an eval credential, then try to use it against a govern-scoped route.
        aid = _register_agent(client, auth_headers, "eval-scope-test")
        cred = client.post(f"/v1/agents/{aid}/credentials/eval", json={
            "name": "no-govern-please",
        }, headers=auth_headers).json()
        eval_key = cred["key"]

        # /v1/agents/{id}/kill requires the 'govern' scope. Eval principal must be blocked.
        r = client.post(f"/v1/agents/{aid}/kill", json={
            "reason": "eval attempt to escalate",
        }, headers={"Authorization": f"Bearer {eval_key}"})
        assert r.status_code == 403
        assert "govern" in r.json()["detail"].lower() or "scope" in r.json()["detail"].lower()

    def test_cannot_issue_eval_cred_for_killed_agent(self, client, auth_headers):
        aid = _register_agent(client, auth_headers, "kill-first-eval")
        client.post(f"/v1/agents/{aid}/kill", json={"reason": "test"}, headers=auth_headers)
        r = client.post(f"/v1/agents/{aid}/credentials/eval", json={"name": "no"},
                        headers=auth_headers)
        assert r.status_code == 409


# ═══════════════════════════════════════════════════════════════════════════
# Batch lockdown
# ═══════════════════════════════════════════════════════════════════════════


class TestBatchLockdown:
    def test_lockdown_affects_only_matching_batch(self, client, auth_headers):
        import uuid as _u
        batch = f"batch-{_u.uuid4().hex[:8]}"
        # Register 3 agents in the batch + 1 outside
        from src.models.database import SessionLocal
        from src.models.agents import AIAgent, AgentType, AgentStatus
        db = SessionLocal()
        try:
            in_batch_ids = []
            for i in range(3):
                a = AIAgent(name=f"lockdown-agent-{batch}-{i}",
                            agent_type=AgentType.AUTONOMOUS,
                            status=AgentStatus.ACTIVE, batch_id=batch)
                db.add(a); db.flush()
                in_batch_ids.append(a.id)
            outside = AIAgent(name=f"outside-{batch}", agent_type=AgentType.AUTONOMOUS,
                              status=AgentStatus.ACTIVE, batch_id=None)
            db.add(outside); db.commit()
            outside_id = outside.id
        finally:
            db.close()

        r = client.post(f"/v1/erg/circuit-breaker/lockdown/{batch}", json={
            "reason": "test lockdown", "triggered_by": "operator",
        }, headers=auth_headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["affected_count"] == 3
        assert set(body["affected_agent_ids"]) == set(in_batch_ids)

        # Outside agent must still be ACTIVE
        from src.models.database import SessionLocal as SL
        db = SL()
        try:
            still = db.query(AIAgent).filter(AIAgent.id == outside_id).first()
            assert still.status == AgentStatus.ACTIVE
        finally:
            db.close()

    def test_lockdown_unknown_batch_404(self, client, auth_headers):
        r = client.post("/v1/erg/circuit-breaker/lockdown/nonexistent", json={
            "reason": "test",
        }, headers=auth_headers)
        assert r.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════
# Spec-gaming detector
# ═══════════════════════════════════════════════════════════════════════════


class TestSpecGamingDetector:
    def test_no_events_when_ledger_clean(self, client, auth_headers):
        aid = _register_agent(client, auth_headers, "clean-agent-sg")
        r = client.post(f"/v1/erg/spec-gaming/scan/{aid}", json={
            "lookback_minutes": 5, "similarity_threshold": 0.9, "auto_escalate": False,
        }, headers=auth_headers)
        assert r.status_code == 200, r.text
        assert r.json()["pattern_events_fired"] == 0

    def test_fires_on_similar_blocked_then_retry(self, client, auth_headers):
        # Register agent + seed AuditRecord rows using the EXACT agent name
        import json
        from src.models.database import SessionLocal, AuditRecord, compute_hash, get_last_hash
        from src.models.agents import AIAgent
        aid = _register_agent(client, auth_headers, "sg-fire-agent")

        db = SessionLocal()
        try:
            agent = db.query(AIAgent).filter(AIAgent.id == aid).first()
            sys_name = agent.name  # match by system_name on AuditRecord
            prev = get_last_hash(db)
            for i, (action, text) in enumerate([
                ("BLOCK",   "agent attempted to write file to artifactory via SSRF"),
                ("APPROVE", "agent attempts to write file to artifactory using webdav"),
            ]):
                did = f"sg-test-{i}-{aid}"
                payload = {"decision_id": did, "reasoning_trace": text, "action": action}
                curr = compute_hash({**payload, "previous_hash": prev})
                db.add(AuditRecord(
                    decision_id=did, system_name=sys_name,
                    industry="test", audited_by="t@e.com",
                    frameworks_audited="TEST",
                    results=json.dumps({"reason": text, "reasoning_trace": text}),
                    risk_score=0.5, risk_level="MEDIUM",
                    governance_action=action, policy_version="test",
                    previous_hash=prev, current_hash=curr,
                ))
                prev = curr
            db.commit()
        finally:
            db.close()

        r = client.post(f"/v1/erg/spec-gaming/scan/{aid}", json={
            "lookback_minutes": 60, "similarity_threshold": 0.3, "auto_escalate": False,
        }, headers=auth_headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["records_inspected"] >= 2
        assert body["pattern_events_fired"] >= 1
        assert "honest_note" in body


# ═══════════════════════════════════════════════════════════════════════════
# Attestation protocol
# ═══════════════════════════════════════════════════════════════════════════


class TestAttestations:
    def _org(self, client, auth_headers):
        import uuid as _u
        slug = f"att-{_u.uuid4().hex[:8]}"
        client.post("/v1/enterprise/orgs", json={"name": "Att Test", "slug": slug},
                    headers=auth_headers)

    def test_emit_returns_signed_attestation(self, client, auth_headers):
        self._org(client, auth_headers)
        r = client.post("/v1/erg/attestations/emit", json={
            "target_system": "artifactory",
            "action_type": "write",
            "scope_summary": "Eval agent will write artifacts to Artifactory during RL run",
            "valid_for_hours": 2,
        }, headers=auth_headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["attestation_id"].startswith("att-")
        assert len(body["signature"]) == 64
        assert body["status"] == "active"
        assert body["protocol_version"] == "erg-attestation-v0-unilateral"

    def test_verify_confirms_signature(self, client, auth_headers):
        self._org(client, auth_headers)
        emit = client.post("/v1/erg/attestations/emit", json={
            "target_system": "s3",
            "action_type": "read",
            "scope_summary": "test read",
        }, headers=auth_headers).json()
        att_id = emit["attestation_id"]

        r = client.get(f"/v1/erg/attestations/{att_id}", headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["signature_valid"] is True

    def test_revoke_flips_status(self, client, auth_headers):
        self._org(client, auth_headers)
        emit = client.post("/v1/erg/attestations/emit", json={
            "target_system": "s3", "action_type": "read", "scope_summary": "test",
        }, headers=auth_headers).json()
        att_id = emit["attestation_id"]

        r = client.post(f"/v1/erg/attestations/{att_id}/revoke", json={
            "reason": "scope change",
        }, headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["status"] == "revoked"

        # Second revoke should 409
        r2 = client.post(f"/v1/erg/attestations/{att_id}/revoke", json={
            "reason": "already done",
        }, headers=auth_headers)
        assert r2.status_code == 409

    def test_list_attestations(self, client, auth_headers):
        self._org(client, auth_headers)
        client.post("/v1/erg/attestations/emit", json={
            "target_system": "hf-hub", "action_type": "probe",
            "scope_summary": "test", "valid_for_hours": 1,
        }, headers=auth_headers)
        r = client.get("/v1/erg/attestations", headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["count"] >= 1
