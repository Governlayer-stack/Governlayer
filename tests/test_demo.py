"""Tests for the public /demo/* endpoints.

Covers:
    - unauthenticated access works (no Authorization header supplied)
    - each of the three scenarios returns the expected structure
    - sessions isolate state — two sessions can't see each other's ledger
    - the accumulated chain verifies intact after N scenarios
    - reset clears the session state cleanly
    - rate limiting kicks in after the configured threshold
"""

import pytest

from src.demo.store import (
    RATE_LIMIT_PER_MINUTE,
    _reset_all_state_for_testing,
)


@pytest.fixture(autouse=True)
def clean_demo_state():
    _reset_all_state_for_testing()
    yield
    _reset_all_state_for_testing()


# ═══════════════════════════════════════════════════════════════════════════
# Endpoint smoke
# ═══════════════════════════════════════════════════════════════════════════


class TestDemoUnauthenticated:
    def test_list_scenarios_no_auth(self, client):
        r = client.get("/demo/scenarios")
        assert r.status_code == 200
        body = r.json()
        assert body["count"] == 3
        names = {s["name"] for s in body["scenarios"]}
        assert names == {"banking", "cyber", "healthcare"}
        assert body["session_id"].startswith("demo-")

    def test_run_banking_returns_ecoa_escalation(self, client):
        r = client.post("/demo/scenarios/banking/run")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["result"]["scenario"] == "banking"
        assert body["result"]["governance_action"] == "ESCALATE_HUMAN"
        esc = body["result"]["escalation"]
        assert esc["violation_type"] == "ECOA"
        assert esc["assigned_reviewer"] == "Compliance Officer (Finance)"
        # Real Reg B reason codes come out of the production catalog
        adverse = body["result"]["adverse_action"]
        assert adverse["ecoa_compliant"] is True
        assert len(adverse["reason_codes"]) >= 1

    def test_run_cyber_blocks_with_framework_citation(self, client):
        r = client.post("/demo/scenarios/cyber/run")
        body = r.json()
        assert body["result"]["governance_action"] == "BLOCK"
        findings = body["result"]["framework_findings"]
        rule_ids = {f["rule_id"] for f in findings}
        assert "ISO_42001.A.7.2" in rule_ids
        # CRITICAL severity present
        assert any(f["severity"] == "CRITICAL" for f in findings)

    def test_run_healthcare_escalates_to_hipaa(self, client):
        r = client.post("/demo/scenarios/healthcare/run")
        body = r.json()
        assert body["result"]["governance_action"] == "ESCALATE_HUMAN"
        esc = body["result"]["escalation"]
        assert esc["violation_type"] == "HIPAA"
        assert esc["assigned_reviewer"] == "Licensed Medical Professional"
        # Real PII findings surfaced in the response
        categories = {f["category"] for f in body["result"]["pii_findings"]}
        assert "SSN" in categories

    def test_unknown_scenario_404(self, client):
        r = client.post("/demo/scenarios/does-not-exist/run")
        assert r.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════
# Session isolation + chain
# ═══════════════════════════════════════════════════════════════════════════


class TestSessionIsolation:
    def test_session_id_persists_via_header(self, client):
        first = client.post("/demo/scenarios/banking/run")
        sid = first.json()["session_id"]
        second = client.post(
            "/demo/scenarios/cyber/run",
            headers={"X-Demo-Session": sid},
        )
        # Same session id echoed back and ledger grew to 2
        assert second.json()["session_id"] == sid
        assert second.json()["ledger_length"] == 2

    def test_two_sessions_do_not_share_state(self, client):
        a = client.post("/demo/scenarios/banking/run").json()["session_id"]
        b = client.post("/demo/scenarios/healthcare/run").json()["session_id"]
        assert a != b

        state_a = client.get(f"/demo/state/{a}").json()
        state_b = client.get(f"/demo/state/{b}").json()
        assert len(state_a["ledger"]) == 1
        assert state_b["ledger"][0]["scenario"] == "healthcare"
        assert state_a["ledger"][0]["scenario"] == "banking"

    def test_chain_intact_after_three_scenarios(self, client):
        first = client.post("/demo/scenarios/banking/run")
        sid = first.json()["session_id"]
        client.post("/demo/scenarios/cyber/run",
                    headers={"X-Demo-Session": sid})
        client.post("/demo/scenarios/healthcare/run",
                    headers={"X-Demo-Session": sid})

        v = client.get(f"/demo/ledger/verify/{sid}").json()
        assert v["status"] == "VERIFIED"
        assert v["chain_intact"] is True
        assert v["records_validated"] == 3
        assert "verification_time_ms" in v

    def test_verify_empty_chain(self, client):
        sid = client.get("/demo/scenarios").json()["session_id"]
        v = client.get(f"/demo/ledger/verify/{sid}").json()
        assert v["chain_intact"] is True
        assert v["records_validated"] == 0

    def test_reset_clears_session(self, client):
        first = client.post("/demo/scenarios/banking/run")
        sid = first.json()["session_id"]
        client.post("/demo/scenarios/cyber/run",
                    headers={"X-Demo-Session": sid})

        client.post(f"/demo/reset/{sid}")
        v = client.get(f"/demo/ledger/verify/{sid}").json()
        assert v["records_validated"] == 0

    def test_state_404_for_unknown_session(self, client):
        r = client.get("/demo/state/does-not-exist")
        assert r.status_code == 404

    def test_verify_404_for_unknown_session(self, client):
        r = client.get("/demo/ledger/verify/does-not-exist")
        assert r.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════
# Rate limiting
# ═══════════════════════════════════════════════════════════════════════════


class TestRateLimit:
    def test_rate_limit_kicks_in(self, client):
        # Send RATE_LIMIT_PER_MINUTE + 1 requests from the same IP.
        # TestClient uses "testclient" as the host by default.
        last_status = None
        for _ in range(RATE_LIMIT_PER_MINUTE + 1):
            r = client.get("/demo/scenarios")
            last_status = r.status_code
            if last_status == 429:
                break
        assert last_status == 429
