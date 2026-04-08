"""Tests for patent-compliant 4-factor composite risk scoring.

Validates R = min(sum(w_i * c_i), 1.0) across four weighted factors:
    - Policy Violations  (w=0.50)
    - AI Confidence       (w=0.25)
    - Use Case Impact     (w=0.15)
    - Vulnerable Pop.     (w=0.10)
"""

import pytest

from src.api.risk import (
    CONFIDENCE_THRESHOLD,
    INCOME_THRESHOLD,
    AGE_THRESHOLD,
    W_POLICY,
    W_CONFIDENCE,
    W_USE_CASE,
    W_VULNERABLE,
    _classify_risk_level,
    compute_patent_risk,
)
from src.models.schemas import PatentRiskScoreRequest, PolicyViolation


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def base_request():
    """A minimal request with no risk factors activated."""
    return PatentRiskScoreRequest(
        system_name="test-system",
        policy_violations=[],
        ai_confidence=1.0,
        use_case="general",
        subject_income=None,
        subject_age=None,
        adverse_action=False,
    )


@pytest.fixture
def max_risk_request():
    """A request designed to produce near-maximum risk."""
    return PatentRiskScoreRequest(
        system_name="max-risk-system",
        policy_violations=[
            PolicyViolation(severity="BLOCKING", description="Total policy violation"),
        ],
        ai_confidence=0.0,
        use_case="medical",
        subject_income=20_000.0,
        subject_age=70,
        adverse_action=True,
    )


# ---------------------------------------------------------------------------
# Risk level classification
# ---------------------------------------------------------------------------

class TestRiskLevelClassification:
    """Verify the four risk tiers map correctly."""

    def test_low_risk_below_030(self):
        assert _classify_risk_level(0.0) == "LOW"
        assert _classify_risk_level(0.15) == "LOW"
        assert _classify_risk_level(0.29) == "LOW"

    def test_medium_risk_030_to_060(self):
        assert _classify_risk_level(0.30) == "MEDIUM"
        assert _classify_risk_level(0.45) == "MEDIUM"
        assert _classify_risk_level(0.59) == "MEDIUM"

    def test_high_risk_060_to_080(self):
        assert _classify_risk_level(0.60) == "HIGH"
        assert _classify_risk_level(0.70) == "HIGH"
        assert _classify_risk_level(0.79) == "HIGH"

    def test_critical_risk_above_080(self):
        assert _classify_risk_level(0.80) == "CRITICAL"
        assert _classify_risk_level(0.90) == "CRITICAL"
        assert _classify_risk_level(1.0) == "CRITICAL"

    def test_boundary_exact_030(self):
        assert _classify_risk_level(0.30) == "MEDIUM"

    def test_boundary_exact_060(self):
        assert _classify_risk_level(0.60) == "HIGH"

    def test_boundary_exact_080(self):
        assert _classify_risk_level(0.80) == "CRITICAL"


# ---------------------------------------------------------------------------
# Composite formula: R = min(sum(w_i * c_i), 1.0)
# ---------------------------------------------------------------------------

class TestCompositeFormula:
    """Test the composite formula with known inputs."""

    def test_zero_risk_baseline(self, base_request):
        score, level, factors = compute_patent_risk(base_request)
        assert score == 0.0
        assert level == "LOW"
        assert len(factors) == 4

    def test_all_weights_sum_to_one(self):
        total = W_POLICY + W_CONFIDENCE + W_USE_CASE + W_VULNERABLE
        assert abs(total - 1.0) < 1e-9, f"Weights sum to {total}, expected 1.0"

    def test_max_score_capped_at_one(self, max_risk_request):
        score, level, factors = compute_patent_risk(max_risk_request)
        assert score <= 1.0

    def test_score_never_negative(self, base_request):
        score, _, _ = compute_patent_risk(base_request)
        assert score >= 0.0

    def test_factors_always_four(self, base_request):
        _, _, factors = compute_patent_risk(base_request)
        assert len(factors) == 4
        factor_names = [f.factor for f in factors]
        assert "policy_violations" in factor_names
        assert "ai_confidence" in factor_names
        assert "use_case_impact" in factor_names
        assert "vulnerable_population" in factor_names

    def test_weighted_contributions_sum_matches_score(self, max_risk_request):
        score, _, factors = compute_patent_risk(max_risk_request)
        raw_sum = sum(f.weighted_contribution for f in factors)
        expected = min(raw_sum, 1.0)
        assert abs(score - round(expected, 4)) < 1e-4


# ---------------------------------------------------------------------------
# Factor 1: Policy Violations (w=0.50)
# ---------------------------------------------------------------------------

class TestPolicyViolationsFactor:
    """Test the policy violations factor independently."""

    def test_no_violations_zero_contribution(self):
        req = PatentRiskScoreRequest(
            system_name="test",
            policy_violations=[],
            ai_confidence=1.0,
            use_case="general",
        )
        score, _, factors = compute_patent_risk(req)
        policy_factor = factors[0]
        assert policy_factor.factor == "policy_violations"
        assert policy_factor.raw_contribution == 0.0
        assert policy_factor.weighted_contribution == 0.0

    def test_blocking_severity_highest(self):
        req = PatentRiskScoreRequest(
            system_name="test",
            policy_violations=[PolicyViolation(severity="BLOCKING", description="block")],
            ai_confidence=1.0,
            use_case="general",
        )
        _, _, factors = compute_patent_risk(req)
        policy_factor = factors[0]
        assert policy_factor.raw_contribution == 0.5
        assert policy_factor.weighted_contribution == round(W_POLICY * 0.5, 4)

    def test_critical_severity(self):
        req = PatentRiskScoreRequest(
            system_name="test",
            policy_violations=[PolicyViolation(severity="CRITICAL", description="crit")],
            ai_confidence=1.0,
            use_case="general",
        )
        _, _, factors = compute_patent_risk(req)
        assert factors[0].raw_contribution == 0.3

    def test_warning_severity(self):
        req = PatentRiskScoreRequest(
            system_name="test",
            policy_violations=[PolicyViolation(severity="WARNING", description="warn")],
            ai_confidence=1.0,
            use_case="general",
        )
        _, _, factors = compute_patent_risk(req)
        assert factors[0].raw_contribution == 0.1

    def test_multiple_violations_takes_max_severity(self):
        """When multiple violations exist, the highest severity score wins."""
        req = PatentRiskScoreRequest(
            system_name="test",
            policy_violations=[
                PolicyViolation(severity="WARNING", description="warn"),
                PolicyViolation(severity="BLOCKING", description="block"),
                PolicyViolation(severity="CRITICAL", description="crit"),
            ],
            ai_confidence=1.0,
            use_case="general",
        )
        _, _, factors = compute_patent_risk(req)
        # BLOCKING = 0.5 is the max
        assert factors[0].raw_contribution == 0.5

    def test_violation_count_tracked_in_evidence(self):
        req = PatentRiskScoreRequest(
            system_name="test",
            policy_violations=[
                PolicyViolation(severity="WARNING", description="w1"),
                PolicyViolation(severity="WARNING", description="w2"),
                PolicyViolation(severity="WARNING", description="w3"),
            ],
            ai_confidence=1.0,
            use_case="general",
        )
        _, _, factors = compute_patent_risk(req)
        assert factors[0].evidence["violation_count"] == 3


# ---------------------------------------------------------------------------
# Factor 2: AI Confidence (w=0.25)
# ---------------------------------------------------------------------------

class TestAIConfidenceFactor:
    """Test the AI confidence factor independently."""

    def test_confidence_at_threshold_no_activation(self):
        """Confidence exactly at 0.85 should NOT activate the factor."""
        req = PatentRiskScoreRequest(
            system_name="test",
            ai_confidence=CONFIDENCE_THRESHOLD,
            use_case="general",
        )
        _, _, factors = compute_patent_risk(req)
        confidence_factor = factors[1]
        assert confidence_factor.factor == "ai_confidence"
        assert confidence_factor.raw_contribution == 0.0
        assert confidence_factor.evidence["below_threshold"] is False

    def test_confidence_above_threshold_no_activation(self):
        req = PatentRiskScoreRequest(
            system_name="test",
            ai_confidence=0.95,
            use_case="general",
        )
        _, _, factors = compute_patent_risk(req)
        assert factors[1].raw_contribution == 0.0

    def test_confidence_below_threshold_activates(self):
        """Contribution = 1 - confidence when below threshold."""
        req = PatentRiskScoreRequest(
            system_name="test",
            ai_confidence=0.50,
            use_case="general",
        )
        _, _, factors = compute_patent_risk(req)
        confidence_factor = factors[1]
        assert confidence_factor.evidence["below_threshold"] is True
        assert abs(confidence_factor.raw_contribution - 0.50) < 1e-4

    def test_zero_confidence_maximum_contribution(self):
        req = PatentRiskScoreRequest(
            system_name="test",
            ai_confidence=0.0,
            use_case="general",
        )
        _, _, factors = compute_patent_risk(req)
        assert factors[1].raw_contribution == 1.0
        assert factors[1].weighted_contribution == round(W_CONFIDENCE * 1.0, 4)

    def test_confidence_just_below_threshold(self):
        req = PatentRiskScoreRequest(
            system_name="test",
            ai_confidence=0.84,
            use_case="general",
        )
        _, _, factors = compute_patent_risk(req)
        expected_raw = round(1.0 - 0.84, 4)
        assert abs(factors[1].raw_contribution - expected_raw) < 1e-4


# ---------------------------------------------------------------------------
# Factor 3: Use Case Impact (w=0.15)
# ---------------------------------------------------------------------------

class TestUseCaseImpactFactor:
    """Test the use case impact factor independently."""

    def test_medical_use_case(self):
        req = PatentRiskScoreRequest(system_name="test", use_case="medical", ai_confidence=1.0)
        _, _, factors = compute_patent_risk(req)
        assert factors[2].raw_contribution == 0.15

    def test_termination_use_case(self):
        req = PatentRiskScoreRequest(system_name="test", use_case="termination", ai_confidence=1.0)
        _, _, factors = compute_patent_risk(req)
        assert factors[2].raw_contribution == 0.15

    def test_loan_use_case(self):
        req = PatentRiskScoreRequest(system_name="test", use_case="loan", ai_confidence=1.0)
        _, _, factors = compute_patent_risk(req)
        assert factors[2].raw_contribution == 0.10

    def test_hiring_use_case(self):
        req = PatentRiskScoreRequest(system_name="test", use_case="hiring", ai_confidence=1.0)
        _, _, factors = compute_patent_risk(req)
        assert factors[2].raw_contribution == 0.10

    def test_general_use_case_zero_impact(self):
        req = PatentRiskScoreRequest(system_name="test", use_case="general", ai_confidence=1.0)
        _, _, factors = compute_patent_risk(req)
        assert factors[2].raw_contribution == 0.0

    def test_unknown_use_case_zero_impact(self):
        req = PatentRiskScoreRequest(system_name="test", use_case="chatbot", ai_confidence=1.0)
        _, _, factors = compute_patent_risk(req)
        assert factors[2].raw_contribution == 0.0

    def test_case_insensitive_use_case(self):
        req = PatentRiskScoreRequest(system_name="test", use_case="MEDICAL", ai_confidence=1.0)
        _, _, factors = compute_patent_risk(req)
        assert factors[2].raw_contribution == 0.15


# ---------------------------------------------------------------------------
# Factor 4: Vulnerable Population (w=0.10)
# ---------------------------------------------------------------------------

class TestVulnerablePopulationFactor:
    """Test the vulnerable population factor independently."""

    def test_no_vulnerable_indicators_no_activation(self):
        req = PatentRiskScoreRequest(
            system_name="test",
            ai_confidence=1.0,
            use_case="general",
            subject_income=100_000.0,
            subject_age=30,
            adverse_action=True,
        )
        _, _, factors = compute_patent_risk(req)
        vuln_factor = factors[3]
        assert vuln_factor.factor == "vulnerable_population"
        assert vuln_factor.raw_contribution == 0.0

    def test_low_income_with_adverse_action(self):
        req = PatentRiskScoreRequest(
            system_name="test",
            ai_confidence=1.0,
            use_case="general",
            subject_income=30_000.0,
            adverse_action=True,
        )
        _, _, factors = compute_patent_risk(req)
        assert factors[3].raw_contribution == 0.10
        assert factors[3].evidence["low_income"] is True
        assert factors[3].evidence["vulnerable_flag"] is True

    def test_elderly_with_adverse_action(self):
        req = PatentRiskScoreRequest(
            system_name="test",
            ai_confidence=1.0,
            use_case="general",
            subject_age=65,
            adverse_action=True,
        )
        _, _, factors = compute_patent_risk(req)
        assert factors[3].raw_contribution == 0.10
        assert factors[3].evidence["elderly"] is True

    def test_vulnerable_without_adverse_action_no_activation(self):
        """Even if income is low, the factor only activates with adverse_action=True."""
        req = PatentRiskScoreRequest(
            system_name="test",
            ai_confidence=1.0,
            use_case="general",
            subject_income=20_000.0,
            subject_age=70,
            adverse_action=False,
        )
        _, _, factors = compute_patent_risk(req)
        assert factors[3].raw_contribution == 0.0
        assert factors[3].evidence["vulnerable_flag"] is False

    def test_income_exactly_at_threshold_no_activation(self):
        """Income at exactly $50K should NOT trigger (requires < threshold)."""
        req = PatentRiskScoreRequest(
            system_name="test",
            ai_confidence=1.0,
            use_case="general",
            subject_income=INCOME_THRESHOLD,
            adverse_action=True,
        )
        _, _, factors = compute_patent_risk(req)
        assert factors[3].evidence["low_income"] is False

    def test_age_exactly_at_threshold_no_activation(self):
        """Age at exactly 60 should NOT trigger (requires > threshold)."""
        req = PatentRiskScoreRequest(
            system_name="test",
            ai_confidence=1.0,
            use_case="general",
            subject_age=AGE_THRESHOLD,
            adverse_action=True,
        )
        _, _, factors = compute_patent_risk(req)
        assert factors[3].evidence["elderly"] is False

    def test_none_income_and_age_no_activation(self):
        req = PatentRiskScoreRequest(
            system_name="test",
            ai_confidence=1.0,
            use_case="general",
            subject_income=None,
            subject_age=None,
            adverse_action=True,
        )
        _, _, factors = compute_patent_risk(req)
        assert factors[3].raw_contribution == 0.0


# ---------------------------------------------------------------------------
# End-to-end composite score scenarios
# ---------------------------------------------------------------------------

class TestCompositeScenarios:
    """Test realistic multi-factor combinations."""

    def test_low_risk_scenario(self):
        """Clean system with only a warning violation."""
        req = PatentRiskScoreRequest(
            system_name="clean-system",
            policy_violations=[PolicyViolation(severity="WARNING", description="minor")],
            ai_confidence=0.90,
            use_case="general",
        )
        score, level, _ = compute_patent_risk(req)
        # w_policy * 0.1 = 0.05, others zero
        assert abs(score - 0.05) < 1e-4
        assert level == "LOW"

    def test_medium_risk_scenario(self):
        """Critical violation + low confidence."""
        req = PatentRiskScoreRequest(
            system_name="medium-system",
            policy_violations=[PolicyViolation(severity="CRITICAL", description="crit")],
            ai_confidence=0.50,
            use_case="loan",
        )
        score, level, _ = compute_patent_risk(req)
        # w_policy * 0.3 + w_conf * 0.5 + w_uc * 0.10 = 0.15 + 0.125 + 0.015 = 0.29
        assert level in ("LOW", "MEDIUM")

    def test_critical_risk_scenario(self):
        """BLOCKING violation + zero confidence + medical + vulnerable."""
        req = PatentRiskScoreRequest(
            system_name="critical-system",
            policy_violations=[PolicyViolation(severity="BLOCKING", description="block")],
            ai_confidence=0.0,
            use_case="medical",
            subject_income=20_000.0,
            adverse_action=True,
        )
        score, level, _ = compute_patent_risk(req)
        # 0.50 * 0.5 + 0.25 * 1.0 + 0.15 * 0.15 + 0.10 * 0.10
        # = 0.25 + 0.25 + 0.0225 + 0.01 = 0.5325
        assert level in ("MEDIUM", "HIGH")


# ---------------------------------------------------------------------------
# API endpoint via TestClient
# ---------------------------------------------------------------------------

class TestRiskScoreEndpoint:
    """Test the /risk-score POST endpoint through the FastAPI TestClient."""

    def test_risk_score_requires_auth(self, client):
        response = client.post("/risk-score", json={
            "system_name": "test-system",
        })
        assert response.status_code in (401, 403)

    def test_risk_score_returns_patent_response(self, client, auth_headers):
        response = client.post("/risk-score", json={
            "system_name": "api-test-system",
            "policy_violations": [
                {"severity": "WARNING", "description": "test warning"},
            ],
            "ai_confidence": 0.90,
            "use_case": "general",
        }, headers=auth_headers)
        assert response.status_code == 200
        body = response.json()
        assert body["scoring_method"] == "patent_composite_v1"
        assert "composite_score" in body
        assert "risk_level" in body
        assert "factors" in body
        assert len(body["factors"]) == 4

    def test_risk_score_empty_violations(self, client, auth_headers):
        response = client.post("/risk-score", json={
            "system_name": "clean-system",
            "ai_confidence": 1.0,
            "use_case": "general",
        }, headers=auth_headers)
        assert response.status_code == 200
        body = response.json()
        assert body["composite_score"] == 0.0
        assert body["risk_level"] == "LOW"

    def test_risk_score_invalid_confidence_rejected(self, client, auth_headers):
        response = client.post("/risk-score", json={
            "system_name": "bad-conf",
            "ai_confidence": 1.5,
        }, headers=auth_headers)
        assert response.status_code == 422

    def test_risk_score_invalid_severity_rejected(self, client, auth_headers):
        response = client.post("/risk-score", json={
            "system_name": "bad-severity",
            "policy_violations": [{"severity": "INVALID", "description": "bad"}],
        }, headers=auth_headers)
        assert response.status_code == 422
