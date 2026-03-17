"""Analytics API — fairness testing, explainability, data drift, security scanning."""

from typing import Dict, List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from src.analytics.fairness import full_fairness_report
from src.analytics.explainability import generate_explanation
from src.analytics.data_drift import feature_drift_report
from src.analytics.guardrails import full_security_scan, redact_pii

router = APIRouter(prefix="/v1/analytics", tags=["Analytics"])


class FairnessRequest(BaseModel):
    predictions: List[int]
    labels: List[int]
    protected_attribute: List[int]
    group_names: Optional[Dict[int, str]] = None


class ExplainRequest(BaseModel):
    feature_names: List[str]
    feature_values: List[float]
    prediction: str
    weights: Optional[List[float]] = None
    num_counterfactuals: int = 3


class DriftRequest(BaseModel):
    reference_data: Dict[str, List[float]]
    current_data: Dict[str, List[float]]


class SecurityScanRequest(BaseModel):
    text: str
    redact: bool = False


@router.post("/fairness")
def test_fairness(data: FairnessRequest):
    """Run bias & fairness analysis on model predictions."""
    group_names = {int(k): v for k, v in data.group_names.items()} if data.group_names else None
    return full_fairness_report(
        predictions=data.predictions,
        labels=data.labels,
        protected_attribute=data.protected_attribute,
        group_names=group_names,
    )


@router.post("/explain")
def explain_prediction(data: ExplainRequest):
    """Generate explainable AI report for a prediction."""
    return generate_explanation(
        feature_names=data.feature_names,
        feature_values=data.feature_values,
        prediction=data.prediction,
        weights=data.weights,
        num_counterfactuals=data.num_counterfactuals,
    )


@router.post("/data-drift")
def detect_data_drift(data: DriftRequest):
    """Detect distribution drift between reference and current data."""
    return feature_drift_report(
        reference_data=data.reference_data,
        current_data=data.current_data,
    )


@router.post("/security-scan")
def security_scan(data: SecurityScanRequest):
    """Scan text for prompt injection attempts and PII."""
    result = full_security_scan(data.text)
    if data.redact:
        result["redacted"] = redact_pii(data.text)
    return result
