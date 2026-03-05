"""Tests for risk scoring logic."""


def test_low_risk_all_safe():
    from src.api.governance import compute_risk_scores
    from src.models.schemas import GovernRequest

    request = GovernRequest(
        system_name="test", use_case="general", reasoning_trace="test",
        ai_decision="test", handles_personal_data=False,
        makes_autonomous_decisions=False, used_in_critical_infrastructure=False,
        has_human_oversight=True, is_explainable=True, has_bias_testing=True,
    )
    scores = compute_risk_scores(request)
    overall = sum(scores.values()) / len(scores)
    assert overall == 100.0


def test_high_risk_all_dangerous():
    from src.api.governance import compute_risk_scores
    from src.models.schemas import GovernRequest

    request = GovernRequest(
        system_name="test", use_case="general", reasoning_trace="test",
        ai_decision="test", handles_personal_data=True,
        makes_autonomous_decisions=True, used_in_critical_infrastructure=True,
        has_human_oversight=False, is_explainable=False, has_bias_testing=False,
    )
    scores = compute_risk_scores(request)
    overall = sum(scores.values()) / len(scores)
    assert overall < 50  # HIGH risk threshold
