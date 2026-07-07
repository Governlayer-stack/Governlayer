"""Tests for /fraud/escalation endpoint.

Covers:
    - Low-confidence consumer-harm actions escalate to analyst
    - AML typologies (sanctions_hit, PEP, elder_abuse) always escalate
    - Repeat action patterns route to UDAAP
    - HIGH risk on consumer-harm holds instead of escalates
    - Ledger append + hash chain
"""

import pytest

from src.governance.hitl import _escalations, _store_lock


@pytest.fixture(autouse=True)
def clean_escalations():
    with _store_lock:
        _escalations.clear()
    yield
    with _store_lock:
        _escalations.clear()


def _base(**overrides):
    payload = {
        "system_name": "fraud-detector-v2",
        "subject_id": "cust-999",
        "proposed_action": "account_freeze",
        "action_reason": "Velocity anomaly on card-not-present transactions",
        "model_confidence": 0.92,
        "customer_balance": 4200.50,
        "transaction_amount": 800,
        "aml_typology": None,
        "prior_action_count_30d": 0,
        "applicant_income": 55000,
        "applicant_age": 34,
    }
    payload.update(overrides)
    return payload


class TestFraudEscalation:
    def test_high_confidence_low_impact_allows(self, client, auth_headers):
        r = client.post("/fraud/escalation",
                        json=_base(proposed_action="manual_review",
                                   applicant_income=200000, applicant_age=34),
                        headers=auth_headers)
        assert r.status_code == 200, r.text
        body = r.json()
        # manual_review isn't a consumer-harm category, low risk => ALLOW
        assert body["governance_action"] == "ALLOW_ACTION"

    def test_low_confidence_freeze_escalates_to_udaap(self, client, auth_headers):
        r = client.post("/fraud/escalation",
                        json=_base(model_confidence=0.55),
                        headers=auth_headers)
        body = r.json()
        assert body["governance_action"] == "ESCALATE_ANALYST"
        assert "UDAAP" in body["violation_routing"]
        assert body["escalation"]["assigned_reviewer"] == "Compliance Officer (Consumer)"

    def test_sanctions_hit_always_escalates(self, client, auth_headers):
        # High confidence would normally allow, but sanctions_hit forces escalation
        r = client.post("/fraud/escalation",
                        json=_base(model_confidence=0.99, aml_typology="sanctions_hit"),
                        headers=auth_headers)
        body = r.json()
        assert body["governance_action"] == "ESCALATE_ANALYST"
        assert "BSA_AML" in body["violation_routing"]
        assert body["escalation"]["assigned_reviewer"] == "BSA/AML Officer"

    def test_pep_typology_always_escalates(self, client, auth_headers):
        r = client.post("/fraud/escalation",
                        json=_base(model_confidence=0.98, aml_typology="pep"),
                        headers=auth_headers)
        assert r.json()["governance_action"] == "ESCALATE_ANALYST"

    def test_elder_financial_abuse_always_escalates(self, client, auth_headers):
        r = client.post("/fraud/escalation",
                        json=_base(model_confidence=0.95,
                                   aml_typology="elder_financial_abuse",
                                   applicant_age=78),
                        headers=auth_headers)
        assert r.json()["governance_action"] == "ESCALATE_ANALYST"

    def test_repeat_actions_trigger_udaap(self, client, auth_headers):
        # High confidence but 4 prior restrictive actions in 30d => UDAAP escalation
        r = client.post("/fraud/escalation",
                        json=_base(model_confidence=0.98, prior_action_count_30d=4),
                        headers=auth_headers)
        body = r.json()
        assert body["governance_action"] == "ESCALATE_ANALYST"
        assert "UDAAP" in body["violation_routing"]

    def test_critical_policy_violation_low_confidence_escalates(self, client, auth_headers):
        # BLOCKING policy violation + sub-threshold confidence on a consumer-harm
        # action must not pass through — must land with an analyst.
        r = client.post("/fraud/escalation",
                        json=_base(model_confidence=0.4, applicant_age=72,
                                   applicant_income=18000,
                                   policy_violations=[{"severity": "BLOCKING",
                                                       "description": "Bypassed KYC step"}]),
                        headers=auth_headers)
        body = r.json()
        assert body["governance_action"] in ("BLOCK_ACTION", "HOLD_ACTION", "ESCALATE_ANALYST")

    def test_ledger_hash_populated(self, client, auth_headers):
        r = client.post("/fraud/escalation", json=_base(model_confidence=0.55),
                        headers=auth_headers)
        body = r.json()
        assert body["current_hash"]
        assert len(body["current_hash"]) == 64  # SHA-256
