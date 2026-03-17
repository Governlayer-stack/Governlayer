import re

from pydantic import BaseModel, Field, field_validator

# Note: password validation enforced on registration only, not login


class UserRegister(BaseModel):
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


class UserLogin(BaseModel):
    email: str = Field(..., max_length=255)
    password: str = Field(..., max_length=72)


class AuditRequest(BaseModel):
    system_name: str = Field(..., min_length=1, max_length=255)
    system_description: str = Field(..., min_length=1, max_length=5000)
    industry: str = Field(..., min_length=1, max_length=255)
    frameworks: str = Field(..., min_length=1, max_length=1000)


class GovernRequest(BaseModel):
    system_name: str = Field(..., min_length=1, max_length=255)
    reasoning_trace: str = Field(..., min_length=1, max_length=10000)
    use_case: str = Field(default="general", max_length=255)
    ai_decision: str | None = Field(default="", max_length=5000)
    handles_personal_data: bool = False
    makes_autonomous_decisions: bool = False
    used_in_critical_infrastructure: bool = False
    has_human_oversight: bool = True
    is_explainable: bool = True
    has_bias_testing: bool = False


class RiskScoreRequest(BaseModel):
    system_name: str = Field(..., min_length=1, max_length=255)
    handles_personal_data: bool = False
    makes_autonomous_decisions: bool = False
    used_in_critical_infrastructure: bool = False
    has_human_oversight: bool = True
    is_explainable: bool = True
    has_bias_testing: bool = False


class ThreatRequest(BaseModel):
    system_type: str = Field(..., min_length=1, max_length=255)
    deployment_context: str = Field(default="production", max_length=255)


class IncidentRequest(BaseModel):
    incident_type: str = Field(..., min_length=1, max_length=255)
    system_name: str = Field(..., min_length=1, max_length=255)
    affected_users: int = Field(ge=0)
    industry: str = Field(..., min_length=1, max_length=255)


class JurisdictionRequest(BaseModel):
    countries: str = Field(..., min_length=1, max_length=1000)
    industry: str = Field(..., min_length=1, max_length=255)
    ai_system_type: str = Field(..., min_length=1, max_length=255)


class DriftRequest(BaseModel):
    reasoning_trace: str = Field(..., min_length=1, max_length=10000)
    use_case: str = Field(default="general", max_length=255)
    threshold: float = Field(default=0.3, ge=0.0, le=1.0)


class ForgotPasswordRequest(BaseModel):
    email: str = Field(..., max_length=255)


class ResetPasswordRequest(BaseModel):
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
