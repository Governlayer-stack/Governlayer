"""Tests for AI credit underwriting oversight.

Covers:
    - Reg B reason-code mapping (specificity + protected-class proxy detection)
    - /credit/oversight decision matrix (block, escalate, deny-with-notice, passthrough)
    - Ledger append + hash chain
    - SR 11-7 document generation
"""

import pytest

from src.credit.reason_codes import pick_reason_codes, catalog
from src.governance.hitl import _escalations, _store_lock


@pytest.fixture(autouse=True)
def clean_escalations():
    with _store_lock:
        _escalations.clear()
    yield
    with _store_lock:
        _escalations.clear()


# ═══════════════════════════════════════════════════════════════════════════
# Reason-code generator
# ═══════════════════════════════════════════════════════════════════════════


class TestReasonCodes:
    def test_catalog_covers_appendix_c_and_extended(self):
        codes = catalog()
        code_ids = {c.code for c in codes}
        assert "INSUFFICIENT_INCOME" in code_ids
        assert "EXCESSIVE_OBLIGATIONS" in code_ids
        assert "BANKRUPTCY" in code_ids
        assert "HIGH_DEBT_TO_INCOME_RATIO" in code_ids  # extended
        assert "SCORE_BELOW_CUTOFF" in code_ids         # extended

    def test_empty_attributions_flags_non_specific(self):
        result = pick_reason_codes({})
        assert result.reason_codes == []
        assert result.ecoa_compliant is False
        assert any("no feature attributions" in w.lower() for w in result.warnings)

    def test_maps_income_to_insufficient_income(self):
        result = pick_reason_codes({"income": 0.9, "credit_score": 0.4})
        assert result.reason_codes[0].code == "INSUFFICIENT_INCOME"
        assert result.ecoa_compliant is True

    def test_top_k_limits_reasons(self):
        attrs = {
            "income": 0.5,
            "debt_to_income": 0.6,
            "credit_score": 0.7,
            "delinquencies_24m": 0.8,
            "recent_inquiries": 0.4,
            "residence_length": 0.3,
        }
        result = pick_reason_codes(attrs, top_k=3)
        assert len(result.reason_codes) == 3

    def test_negative_contributions_are_ignored(self):
        # income helped applicant (negative contribution) — should not appear
        result = pick_reason_codes({"income": -0.7, "delinquencies_24m": 0.3})
        codes = [rc.code for rc in result.reason_codes]
        assert "INSUFFICIENT_INCOME" not in codes
        assert "DELINQUENT_CREDIT_OBLIGATIONS" in codes

    def test_protected_class_flagged_and_blocks_compliance(self):
        result = pick_reason_codes({
            "zip_code": 0.6,
            "income": 0.5,
        })
        assert "zip_code" in result.protected_class_flags
        # Even with a specific reason, protected-class proxy blocks ecoa_compliant
        assert result.ecoa_compliant is False
        assert any("fair-lending" in w.lower() for w in result.warnings)

    def test_unmatched_feature_warns_but_does_not_block(self):
        result = pick_reason_codes({
            "income": 0.9,
            "novel_alt_data_signal": 0.4,
        })
        assert result.ecoa_compliant is True
        assert result.unmatched_features == ["novel_alt_data_signal"]

    def test_statement_includes_reg_b_notice(self):
        result = pick_reason_codes(
            {"delinquencies_24m": 0.9}, creditor_name="Acme Bank"
        )
        assert "Acme Bank" in result.statement
        assert "Equal Credit Opportunity Act" in result.statement
        assert "Delinquent past or present credit obligations" in result.statement


# ═══════════════════════════════════════════════════════════════════════════
# /credit/oversight endpoint
# ═══════════════════════════════════════════════════════════════════════════


def _base_payload(**overrides):
    payload = {
        "system_name": "credit-model-v3",
        "application_id": "APP-12345",
        "proposed_decision": "deny",
        "model_confidence": 0.92,
        "feature_attributions": {"delinquencies_24m": 0.85, "debt_to_income": 0.4},
        "loan_type": "unsecured_consumer",
        "requested_amount": 15000,
        "applicant_income": 62000,
        "applicant_age": 35,
        "creditor_name": "TestBank",
    }
    payload.update(overrides)
    return payload


class TestCreditOversightEndpoint:
    def test_clean_denial_gets_notice(self, client, auth_headers):
        r = client.post("/credit/oversight", json=_base_payload(), headers=auth_headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["governance_action"] == "DENY_WITH_NOTICE"
        assert body["adverse_action"]["ecoa_compliant"] is True
        assert any(
            rc["code"] == "DELINQUENT_CREDIT_OBLIGATIONS"
            for rc in body["adverse_action"]["reason_codes"]
        )
        assert body["current_hash"]  # hash chain populated

    def test_borderline_denial_escalates(self, client, auth_headers):
        r = client.post(
            "/credit/oversight",
            json=_base_payload(model_confidence=0.6),
            headers=auth_headers,
        )
        body = r.json()
        assert body["governance_action"] == "ESCALATE_HUMAN"
        assert body["escalation"]["assigned_reviewer"] == "Compliance Officer (Finance)"
        assert body["escalation"]["violation_type"] == "ECOA"

    def test_protected_class_proxy_blocks_notice(self, client, auth_headers):
        r = client.post(
            "/credit/oversight",
            json=_base_payload(
                feature_attributions={
                    "zip_code": 0.7,
                    "delinquencies_24m": 0.3,
                },
            ),
            headers=auth_headers,
        )
        body = r.json()
        assert body["governance_action"] == "BLOCK"
        assert "zip_code" in body["fair_lending_flags"]

    def test_approval_passes_through(self, client, auth_headers):
        r = client.post(
            "/credit/oversight",
            json=_base_payload(
                proposed_decision="approve",
                feature_attributions={},
            ),
            headers=auth_headers,
        )
        body = r.json()
        assert body["governance_action"] == "APPROVE_PASSTHROUGH"
        assert body["adverse_action"] is None

    def test_denial_with_no_attributions_escalates(self, client, auth_headers):
        r = client.post(
            "/credit/oversight",
            json=_base_payload(feature_attributions={}),
            headers=auth_headers,
        )
        body = r.json()
        assert body["governance_action"] == "ESCALATE_HUMAN"
        assert body["adverse_action"]["ecoa_compliant"] is False

    def test_reason_codes_list_endpoint(self, client, auth_headers):
        r = client.get("/credit/reason-codes", headers=auth_headers)
        assert r.status_code == 200
        body = r.json()
        assert body["count"] > 0
        codes = {rc["code"] for rc in body["reason_codes"]}
        assert "INSUFFICIENT_INCOME" in codes

    def test_sr26_2_document(self, client, auth_headers):
        # Seed a couple of decisions first
        client.post("/credit/oversight", json=_base_payload(application_id="A1"),
                    headers=auth_headers)
        client.post("/credit/oversight",
                    json=_base_payload(application_id="A2", proposed_decision="approve",
                                       feature_attributions={}),
                    headers=auth_headers)

        r = client.get("/credit/sr26-2/credit-model-v3?window_days=30",
                       headers=auth_headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["framework"] == "SR 26-2 / OCC 2026-13"
        assert "Replaces SR 11-7" in body["framework_lineage"]
        assert "V_3_ongoing_monitoring" in body["sections"]
        assert "V_4_outcomes_analysis" in body["sections"]
        assert body["sections"]["V_4_outcomes_analysis"]["approve_count"] >= 1

    def test_sr11_7_alias_still_works_with_deprecation_header(self, client, auth_headers):
        # Seed at least one decision so the doc has content
        client.post("/credit/oversight", json=_base_payload(application_id="A3"),
                    headers=auth_headers)

        r = client.get("/credit/sr11-7/credit-model-v3?window_days=30",
                       headers=auth_headers)
        assert r.status_code == 200, r.text
        assert r.headers.get("Deprecation") == "true"
        assert "Sunset" in r.headers
        assert r.headers.get("Link", "").endswith('rel="successor-version"')
        # Body content is the same SR 26-2 doc
        assert r.json()["framework"] == "SR 26-2 / OCC 2026-13"
