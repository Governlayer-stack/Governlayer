import re
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator

# Note: password validation enforced on registration only, not login

# Simple regex to strip HTML tags — no extra dependencies needed
_HTML_TAG_RE = re.compile(r"<[^>]+>")


def _strip_html(value: str) -> str:
    """Remove HTML tags from a string."""
    return _HTML_TAG_RE.sub("", value)


class _SanitizedModel(BaseModel):
    """Base model that strips HTML tags from all string fields."""

    @model_validator(mode="after")
    def strip_html_tags(self):
        for field_name, field_info in type(self).model_fields.items():
            value = getattr(self, field_name)
            if isinstance(value, str):
                setattr(self, field_name, _strip_html(value))
        return self


class UserRegister(_SanitizedModel):
    email: str = Field(..., max_length=255)
    password: str = Field(..., min_length=8, max_length=72)
    company: str = Field(..., min_length=1, max_length=255)

    @field_validator("email")
    @classmethod
    def validate_email(cls, v):
        if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", v):
            raise ValueError("Invalid email format")
        return v.lower()

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"[0-9]", v):
            raise ValueError("Password must contain at least one digit")
        return v


class UserLogin(_SanitizedModel):
    email: str = Field(..., max_length=255)
    password: str = Field(..., max_length=72)
    mfa_code: Optional[str] = Field(default=None, max_length=8)


class AuditRequest(_SanitizedModel):
    system_name: str = Field(..., min_length=1, max_length=255)
    system_description: str = Field(..., min_length=1, max_length=5000)
    industry: str = Field(..., min_length=1, max_length=100)
    frameworks: str = Field(..., min_length=1, max_length=1000)

    @field_validator("system_name")
    @classmethod
    def strip_system_name(cls, v):
        return v.strip()


class GovernRequest(_SanitizedModel):
    system_name: str = Field(..., min_length=1, max_length=255)
    reasoning_trace: str = Field(..., min_length=1, max_length=50000)
    use_case: str = Field(default="general", max_length=1000)
    ai_decision: str | None = Field(default="", max_length=5000)
    handles_personal_data: bool = False
    makes_autonomous_decisions: bool = False
    used_in_critical_infrastructure: bool = False
    has_human_oversight: bool = True
    is_explainable: bool = True
    has_bias_testing: bool = False

    @field_validator("system_name")
    @classmethod
    def strip_system_name(cls, v):
        return v.strip()


class RiskScoreRequest(_SanitizedModel):
    system_name: str = Field(..., min_length=1, max_length=255)
    handles_personal_data: bool = False
    makes_autonomous_decisions: bool = False
    used_in_critical_infrastructure: bool = False
    has_human_oversight: bool = True
    is_explainable: bool = True
    has_bias_testing: bool = False

    @field_validator("system_name")
    @classmethod
    def strip_system_name(cls, v):
        return v.strip()


# ---------------------------------------------------------------------------
# Patent-compliant risk scoring (4 weighted factors)
# ---------------------------------------------------------------------------


class PolicyViolation(_SanitizedModel):
    """A single policy violation detected during evaluation."""
    severity: str = Field(..., pattern=r"^(BLOCKING|CRITICAL|WARNING)$", description="BLOCKING, CRITICAL, or WARNING")
    description: str = Field(default="", max_length=1000)


class PatentRiskScoreRequest(_SanitizedModel):
    """Request body for the patent-compliant composite risk score.

    The four weighted factors are:
      1. Policy Violations  (w=0.50) -- list of violations with severity
      2. AI Confidence      (w=0.25) -- model confidence score [0,1]
      3. Use Case Impact    (w=0.15) -- use-case category string
      4. Vulnerable Pop.    (w=0.10) -- income, age, adverse action flag
    """
    system_name: str = Field(..., min_length=1, max_length=255)

    # Factor 1: Policy violations
    policy_violations: list[PolicyViolation] = Field(default_factory=list)

    # Factor 2: AI confidence
    ai_confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Model confidence score 0-1")

    # Factor 3: Use-case impact category
    use_case: str = Field(default="general", max_length=255, description="e.g. medical, termination, loan, hiring, general")

    # Factor 4: Vulnerable population indicators
    subject_income: Optional[float] = Field(default=None, ge=0, description="Annual income in USD")
    subject_age: Optional[int] = Field(default=None, ge=0, le=150, description="Age of affected individual")
    adverse_action: bool = Field(default=False, description="Whether the AI decision is an adverse action")

    @field_validator("system_name")
    @classmethod
    def strip_system_name(cls, v):
        return v.strip()


class FactorEvidence(BaseModel):
    """Evidence breakdown for a single risk factor."""
    factor: str
    weight: float
    raw_contribution: float = Field(description="Unweighted contribution c_i (0-1)")
    weighted_contribution: float = Field(description="w_i * c_i")
    evidence: dict = Field(default_factory=dict, description="Raw data values, thresholds, gap analysis")


class PatentRiskScoreResponse(BaseModel):
    """Response for patent-compliant risk scoring."""
    system: str
    scoring_method: str = "patent_composite_v1"
    composite_score: float = Field(description="R = min(sum(w_i * c_i), 1.0)")
    risk_level: str = Field(description="LOW / MEDIUM / HIGH / CRITICAL")
    factors: list[FactorEvidence]
    scored_by: str
    scored_at: str


class ThreatRequest(_SanitizedModel):
    system_type: str = Field(..., min_length=1, max_length=255)
    deployment_context: str = Field(default="production", max_length=255)


class IncidentRequest(_SanitizedModel):
    incident_type: str = Field(..., min_length=1, max_length=255)
    system_name: str = Field(..., min_length=1, max_length=255)
    affected_users: int = Field(ge=0)
    industry: str = Field(..., min_length=1, max_length=100)


class JurisdictionRequest(_SanitizedModel):
    countries: str = Field(..., min_length=1, max_length=1000)
    industry: str = Field(..., min_length=1, max_length=100)
    ai_system_type: str = Field(..., min_length=1, max_length=255)


class DriftRequest(_SanitizedModel):
    reasoning_trace: str = Field(..., min_length=1, max_length=50000)
    use_case: str = Field(default="general", max_length=1000)
    threshold: float = Field(default=0.3, ge=0.0, le=1.0)


class ForgotPasswordRequest(_SanitizedModel):
    email: str = Field(..., max_length=255)


class ResetPasswordRequest(_SanitizedModel):
    token: str = Field(..., min_length=32, max_length=64)
    new_password: str = Field(..., min_length=8, max_length=72)

    @field_validator("new_password")
    @classmethod
    def validate_password(cls, v):
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"[0-9]", v):
            raise ValueError("Password must contain at least one digit")
        return v
