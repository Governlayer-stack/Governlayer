"""Risk scoring endpoints.

Primary: patent-compliant 4-factor composite scoring (POST /risk-score).
Legacy:  6-dimension boolean scoring (POST /risk-score/legacy).
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.models.database import RiskScoreRecord, get_db
from src.models.schemas import (
    FactorEvidence,
    PatentRiskScoreRequest,
    PatentRiskScoreResponse,
    RiskScoreRequest,
)
from src.security.auth import verify_token

router = APIRouter(tags=["risk"])

# ---------------------------------------------------------------------------
# Severity contribution map for policy violations (Factor 1)
# ---------------------------------------------------------------------------
_SEVERITY_SCORE = {
    "BLOCKING": 0.5,
    "CRITICAL": 0.3,
    "WARNING": 0.1,
}

# ---------------------------------------------------------------------------
# Use-case impact map (Factor 3)
# ---------------------------------------------------------------------------
_USE_CASE_IMPACT = {
    "medical": 0.15,
    "termination": 0.15,
    "loan": 0.10,
    "hiring": 0.10,
}

# ---------------------------------------------------------------------------
# Patent weights
# ---------------------------------------------------------------------------
W_POLICY = 0.50
W_CONFIDENCE = 0.25
W_USE_CASE = 0.15
W_VULNERABLE = 0.10

# Confidence threshold below which the factor activates
CONFIDENCE_THRESHOLD = 0.85

# Vulnerable population thresholds
INCOME_THRESHOLD = 50_000.0
AGE_THRESHOLD = 60


def _classify_risk_level(r: float) -> str:
    """Map composite score R to risk level per patent spec."""
    if r >= 0.80:
        return "CRITICAL"
    if r >= 0.60:
        return "HIGH"
    if r >= 0.30:
        return "MEDIUM"
    return "LOW"


def compute_patent_risk(request: PatentRiskScoreRequest) -> tuple[float, str, list[FactorEvidence]]:
    """Compute the patent-compliant composite risk score.

    R = min(sum(w_i * c_i), 1.0) across four weighted factors.
    Returns (composite_score, risk_level, factor_evidence_list).
    """
    factors: list[FactorEvidence] = []

    # ---- Factor 1: Policy Violations (w=0.50) ----
    # Take the *highest* severity found among all violations.
    if request.policy_violations:
        max_severity_score = max(
            _SEVERITY_SCORE.get(v.severity, 0.0) for v in request.policy_violations
        )
        c_policy = max_severity_score
        severities = [v.severity for v in request.policy_violations]
    else:
        c_policy = 0.0
        severities = []

    factors.append(FactorEvidence(
        factor="policy_violations",
        weight=W_POLICY,
        raw_contribution=round(c_policy, 4),
        weighted_contribution=round(W_POLICY * c_policy, 4),
        evidence={
            "violation_count": len(request.policy_violations),
            "severities": severities,
            "max_severity_score": round(c_policy, 4),
            "threshold_map": _SEVERITY_SCORE,
        },
    ))

    # ---- Factor 2: AI Confidence (w=0.25) ----
    # Activates when confidence < 0.85: contribution = 1 - confidence
    if request.ai_confidence < CONFIDENCE_THRESHOLD:
        c_confidence = 1.0 - request.ai_confidence
    else:
        c_confidence = 0.0

    gap = round(CONFIDENCE_THRESHOLD - request.ai_confidence, 4) if request.ai_confidence < CONFIDENCE_THRESHOLD else 0.0
    factors.append(FactorEvidence(
        factor="ai_confidence",
        weight=W_CONFIDENCE,
        raw_contribution=round(c_confidence, 4),
        weighted_contribution=round(W_CONFIDENCE * c_confidence, 4),
        evidence={
            "reported_confidence": request.ai_confidence,
            "threshold": CONFIDENCE_THRESHOLD,
            "below_threshold": request.ai_confidence < CONFIDENCE_THRESHOLD,
            "gap": gap,
        },
    ))

    # ---- Factor 3: Use Case Impact (w=0.15) ----
    use_case_key = request.use_case.lower().strip()
    c_use_case = _USE_CASE_IMPACT.get(use_case_key, 0.0)

    factors.append(FactorEvidence(
        factor="use_case_impact",
        weight=W_USE_CASE,
        raw_contribution=round(c_use_case, 4),
        weighted_contribution=round(W_USE_CASE * c_use_case, 4),
        evidence={
            "use_case": request.use_case,
            "matched_category": use_case_key if use_case_key in _USE_CASE_IMPACT else None,
            "impact_score": round(c_use_case, 4),
            "impact_map": _USE_CASE_IMPACT,
        },
    ))

    # ---- Factor 4: Vulnerable Population (w=0.10) ----
    # Activates if (income < $50K OR age > 60) AND adverse_action is True
    low_income = request.subject_income is not None and request.subject_income < INCOME_THRESHOLD
    elderly = request.subject_age is not None and request.subject_age > AGE_THRESHOLD
    vulnerable = (low_income or elderly) and request.adverse_action
    c_vulnerable = 0.10 if vulnerable else 0.0

    factors.append(FactorEvidence(
        factor="vulnerable_population",
        weight=W_VULNERABLE,
        raw_contribution=round(c_vulnerable, 4),
        weighted_contribution=round(W_VULNERABLE * c_vulnerable, 4),
        evidence={
            "subject_income": request.subject_income,
            "income_threshold": INCOME_THRESHOLD,
            "low_income": low_income,
            "subject_age": request.subject_age,
            "age_threshold": AGE_THRESHOLD,
            "elderly": elderly,
            "adverse_action": request.adverse_action,
            "vulnerable_flag": vulnerable,
        },
    ))

    # ---- Composite ----
    composite = min(sum(f.weighted_contribution for f in factors), 1.0)
    composite = round(composite, 4)
    risk_level = _classify_risk_level(composite)

    return composite, risk_level, factors


# ---------------------------------------------------------------------------
# Primary endpoint: patent-compliant scoring
# ---------------------------------------------------------------------------
@router.post("/risk-score", response_model=PatentRiskScoreResponse)
def risk_score(
    request: PatentRiskScoreRequest,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    """Patent-compliant composite risk scoring.

    R = min(sum(w_i * c_i), 1.0) across 4 weighted factors:
      - Policy Violations (0.50)
      - AI Confidence (0.25)
      - Use Case Impact (0.15)
      - Vulnerable Population (0.10)
    """
    composite, risk_level, factors = compute_patent_risk(request)

    # Persist to existing RiskScoreRecord table for audit trail.
    # Map patent factors into the legacy columns (best-effort).
    record = RiskScoreRecord(
        system_name=request.system_name,
        overall_score=composite,
        risk_level=risk_level,
        privacy_score=factors[0].weighted_contribution,   # policy violations
        autonomy_score=factors[1].weighted_contribution,  # ai confidence
        infrastructure_score=factors[2].weighted_contribution,  # use case impact
        oversight_score=factors[3].weighted_contribution,  # vulnerable pop
        transparency_score=0.0,
        fairness_score=0.0,
        scored_by=email,
    )
    db.add(record)
    db.commit()

    return PatentRiskScoreResponse(
        system=request.system_name,
        composite_score=composite,
        risk_level=risk_level,
        factors=factors,
        scored_by=email,
        scored_at=datetime.now(timezone.utc).isoformat(),
    )


# ---------------------------------------------------------------------------
# Legacy endpoint: 6-dimension boolean scoring
# ---------------------------------------------------------------------------
@router.post("/risk-score/legacy")
def risk_score_legacy(
    request: RiskScoreRequest,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    """Legacy 6-dimension boolean risk scoring (backwards compatible)."""
    scores = {
        "Privacy": 100 if not request.handles_personal_data else 40,
        "Autonomy_Risk": 100 if not request.makes_autonomous_decisions else 30,
        "Infrastructure_Risk": 100 if not request.used_in_critical_infrastructure else 25,
        "Oversight": 100 if request.has_human_oversight else 20,
        "Transparency": 100 if request.is_explainable else 30,
        "Fairness": 100 if request.has_bias_testing else 25,
    }
    overall = sum(scores.values()) / len(scores)
    risk_level = "LOW" if overall >= 80 else "MEDIUM" if overall >= 50 else "HIGH"

    record = RiskScoreRecord(
        system_name=request.system_name,
        overall_score=round(overall),
        risk_level=risk_level,
        privacy_score=scores["Privacy"],
        autonomy_score=scores["Autonomy_Risk"],
        infrastructure_score=scores["Infrastructure_Risk"],
        oversight_score=scores["Oversight"],
        transparency_score=scores["Transparency"],
        fairness_score=scores["Fairness"],
        scored_by=email,
    )
    db.add(record)
    db.commit()

    return {
        "system": request.system_name,
        "overall_score": round(overall),
        "risk_level": risk_level,
        "dimension_scores": scores,
        "scored_by": email,
        "scored_at": datetime.now(timezone.utc).isoformat(),
    }
