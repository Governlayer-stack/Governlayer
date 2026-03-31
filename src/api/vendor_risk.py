"""Vendor Risk Management API — third-party AI vendor assessment and monitoring."""

import uuid
from datetime import datetime, date
from enum import Enum
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from src.security.auth import verify_token

router = APIRouter(prefix="/v1/vendors", tags=["Vendor Risk"])


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class VendorCategory(str, Enum):
    AI_PLATFORM = "ai_platform"
    DATA_PROVIDER = "data_provider"
    CLOUD_INFRASTRUCTURE = "cloud_infrastructure"
    SAAS_APPLICATION = "saas_application"
    CONSULTING = "consulting"
    HARDWARE = "hardware"
    OTHER = "other"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class QuestionnaireStatus(str, Enum):
    NOT_SENT = "not_sent"
    SENT = "sent"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    OVERDUE = "overdue"


# ---------------------------------------------------------------------------
# Pydantic models — requests
# ---------------------------------------------------------------------------

class VendorCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    category: VendorCategory = VendorCategory.AI_PLATFORM
    services: list[str] = Field(default_factory=list, description="Services provided by this vendor")
    data_shared: list[str] = Field(
        default_factory=list,
        description="Types of data shared with vendor (e.g. PII, PHI, financial, behavioral, anonymized)",
    )
    ai_usage: str = Field(
        default="none",
        max_length=1000,
        description="How the vendor uses AI in their service delivery",
    )
    compliance_certifications: list[str] = Field(
        default_factory=list,
        description="Certifications held (SOC2, ISO27001, HIPAA, GDPR, FedRAMP, etc.)",
    )
    contract_end_date: Optional[date] = Field(
        default=None, description="Contract expiration date (YYYY-MM-DD)"
    )
    contact_email: Optional[str] = Field(default=None, max_length=255)
    notes: Optional[str] = Field(default=None, max_length=5000)


class VendorUpdate(BaseModel):
    name: Optional[str] = Field(default=None, max_length=255)
    category: Optional[VendorCategory] = None
    services: Optional[list[str]] = None
    data_shared: Optional[list[str]] = None
    ai_usage: Optional[str] = Field(default=None, max_length=1000)
    compliance_certifications: Optional[list[str]] = None
    contract_end_date: Optional[date] = None
    contact_email: Optional[str] = Field(default=None, max_length=255)
    notes: Optional[str] = Field(default=None, max_length=5000)


class QuestionnaireRequest(BaseModel):
    contact_email: Optional[str] = Field(
        default=None, max_length=255, description="Override recipient email"
    )
    sections: list[str] = Field(
        default_factory=lambda: [
            "data_handling",
            "access_controls",
            "incident_response",
            "ai_governance",
            "subprocessors",
        ],
        description="Questionnaire sections to include",
    )


# ---------------------------------------------------------------------------
# Pydantic models — responses
# ---------------------------------------------------------------------------

class RiskAssessment(BaseModel):
    data_sensitivity_score: int = Field(..., ge=0, le=100)
    ai_dependency_score: int = Field(..., ge=0, le=100)
    compliance_score: int = Field(..., ge=0, le=100)
    contract_risk_score: int = Field(..., ge=0, le=100)
    concentration_risk_score: int = Field(..., ge=0, le=100)
    overall_risk_score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    assessed_at: str
    assessed_by: str


# ---------------------------------------------------------------------------
# In-memory storage
# ---------------------------------------------------------------------------

_vendors: dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

# Weights for overall risk (must sum to 1.0)
_WEIGHTS = {
    "data_sensitivity": 0.30,
    "ai_dependency": 0.20,
    "compliance": 0.20,
    "contract_risk": 0.15,
    "concentration_risk": 0.15,
}

# Data types ranked by sensitivity (higher = more sensitive)
_DATA_SENSITIVITY = {
    "phi": 100,
    "pii": 90,
    "financial": 80,
    "biometric": 85,
    "behavioral": 60,
    "usage_analytics": 40,
    "anonymized": 15,
    "public": 5,
}

# Certification risk reductions
_CERT_SCORES = {
    "soc2": 20,
    "soc2_type2": 25,
    "iso27001": 20,
    "iso42001": 15,
    "hipaa": 15,
    "gdpr": 15,
    "fedramp": 20,
    "pci_dss": 15,
    "nist_csf": 10,
    "nist_ai_rmf": 10,
    "eu_ai_act": 10,
    "ccpa": 10,
}


def _score_data_sensitivity(data_shared: list[str]) -> int:
    """0 = no sensitive data, 100 = maximum sensitivity."""
    if not data_shared:
        return 10  # unknown data sharing is still a mild risk
    scores = []
    for dtype in data_shared:
        normalized = dtype.lower().strip().replace(" ", "_")
        scores.append(_DATA_SENSITIVITY.get(normalized, 50))
    return min(100, max(scores))


def _score_ai_dependency(ai_usage: str, services: list[str]) -> int:
    """0 = no AI dependency, 100 = fully dependent on vendor AI."""
    if not ai_usage or ai_usage.lower() in ("none", "n/a", ""):
        return 10

    score = 30  # baseline if any AI usage declared
    usage_lower = ai_usage.lower()

    if any(kw in usage_lower for kw in ("core", "critical", "primary", "essential")):
        score += 40
    if any(kw in usage_lower for kw in ("autonomous", "automated decision", "real-time")):
        score += 20
    if any(kw in usage_lower for kw in ("training", "fine-tun", "model")):
        score += 10

    # More services = higher dependency
    score += min(20, len(services) * 5)

    return min(100, score)


def _score_compliance(certifications: list[str]) -> int:
    """0 = fully compliant (no risk), 100 = no certifications (max risk).

    This is inverted: more certs = lower risk score.
    """
    if not certifications:
        return 95  # no certifications is very risky

    total_reduction = 0
    for cert in certifications:
        normalized = cert.lower().strip().replace(" ", "_").replace("-", "_")
        total_reduction += _CERT_SCORES.get(normalized, 5)

    # Start at 95 risk, reduce by certifications
    return max(0, 95 - total_reduction)


def _score_contract_risk(contract_end_date: Optional[date]) -> int:
    """0 = long-term contract, 100 = expired or expiring imminently."""
    if contract_end_date is None:
        return 60  # no contract date is moderate risk

    today = date.today()
    days_remaining = (contract_end_date - today).days

    if days_remaining < 0:
        return 100  # expired
    if days_remaining <= 30:
        return 90
    if days_remaining <= 90:
        return 70
    if days_remaining <= 180:
        return 50
    if days_remaining <= 365:
        return 30
    return 10  # more than a year out


def _score_concentration_risk(services: list[str]) -> int:
    """0 = single service, 100 = many services from one vendor."""
    count = len(services)
    if count <= 1:
        return 15
    if count <= 2:
        return 30
    if count <= 4:
        return 55
    if count <= 6:
        return 75
    return 95


def _assess_vendor(vendor: dict, assessed_by: str) -> dict:
    """Run deterministic risk assessment on a vendor and return scores."""
    data_sens = _score_data_sensitivity(vendor["data_shared"])
    ai_dep = _score_ai_dependency(vendor["ai_usage"], vendor["services"])
    compliance = _score_compliance(vendor["compliance_certifications"])
    contract = _score_contract_risk(
        date.fromisoformat(vendor["contract_end_date"])
        if vendor.get("contract_end_date")
        else None
    )
    concentration = _score_concentration_risk(vendor["services"])

    overall = round(
        data_sens * _WEIGHTS["data_sensitivity"]
        + ai_dep * _WEIGHTS["ai_dependency"]
        + compliance * _WEIGHTS["compliance"]
        + contract * _WEIGHTS["contract_risk"]
        + concentration * _WEIGHTS["concentration_risk"]
    )

    if overall >= 80:
        level = RiskLevel.CRITICAL
    elif overall >= 60:
        level = RiskLevel.HIGH
    elif overall >= 40:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.LOW

    assessment = {
        "data_sensitivity_score": data_sens,
        "ai_dependency_score": ai_dep,
        "compliance_score": compliance,
        "contract_risk_score": contract,
        "concentration_risk_score": concentration,
        "overall_risk_score": overall,
        "risk_level": level.value,
        "assessed_at": datetime.utcnow().isoformat(),
        "assessed_by": assessed_by,
    }
    return assessment


def _vendor_response(vendor: dict) -> dict:
    """Build a safe response dict from internal vendor record."""
    return {
        "id": vendor["id"],
        "name": vendor["name"],
        "category": vendor["category"],
        "services": vendor["services"],
        "data_shared": vendor["data_shared"],
        "ai_usage": vendor["ai_usage"],
        "compliance_certifications": vendor["compliance_certifications"],
        "contract_end_date": vendor.get("contract_end_date"),
        "contact_email": vendor.get("contact_email"),
        "notes": vendor.get("notes"),
        "questionnaire_status": vendor.get("questionnaire_status", QuestionnaireStatus.NOT_SENT.value),
        "risk_assessment": vendor.get("risk_assessment"),
        "created_at": vendor["created_at"],
        "updated_at": vendor["updated_at"],
        "created_by": vendor["created_by"],
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("", status_code=201)
def create_vendor(body: VendorCreate, email: str = Depends(verify_token)):
    """Register a new third-party vendor for risk tracking."""
    vendor_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()

    vendor = {
        "id": vendor_id,
        "name": body.name,
        "category": body.category.value,
        "services": body.services,
        "data_shared": body.data_shared,
        "ai_usage": body.ai_usage,
        "compliance_certifications": body.compliance_certifications,
        "contract_end_date": body.contract_end_date.isoformat() if body.contract_end_date else None,
        "contact_email": body.contact_email,
        "notes": body.notes,
        "questionnaire_status": QuestionnaireStatus.NOT_SENT.value,
        "risk_assessment": None,
        "created_at": now,
        "updated_at": now,
        "created_by": email,
    }
    _vendors[vendor_id] = vendor
    return _vendor_response(vendor)


@router.get("")
def list_vendors(email: str = Depends(verify_token)):
    """List all registered vendors with their latest risk scores."""
    results = []
    for v in _vendors.values():
        resp = _vendor_response(v)
        # Include a summary risk level for list view
        ra = v.get("risk_assessment")
        resp["overall_risk_score"] = ra["overall_risk_score"] if ra else None
        resp["risk_level"] = ra["risk_level"] if ra else None
        results.append(resp)
    return {"total": len(results), "vendors": results}


@router.get("/summary")
def vendor_summary(email: str = Depends(verify_token)):
    """Dashboard summary: total vendors, high-risk count, expiring contracts, assessment coverage."""
    total = len(_vendors)
    assessed = 0
    high_risk = 0
    critical_risk = 0
    expiring_30d = 0
    expiring_90d = 0
    by_category: dict[str, int] = {}

    today = date.today()

    for v in _vendors.values():
        # Category breakdown
        cat = v["category"]
        by_category[cat] = by_category.get(cat, 0) + 1

        # Assessment coverage
        ra = v.get("risk_assessment")
        if ra:
            assessed += 1
            if ra["risk_level"] == RiskLevel.HIGH.value:
                high_risk += 1
            elif ra["risk_level"] == RiskLevel.CRITICAL.value:
                critical_risk += 1

        # Expiring contracts
        if v.get("contract_end_date"):
            end = date.fromisoformat(v["contract_end_date"])
            days_left = (end - today).days
            if 0 <= days_left <= 30:
                expiring_30d += 1
            elif 0 <= days_left <= 90:
                expiring_90d += 1

    return {
        "total_vendors": total,
        "assessed_vendors": assessed,
        "assessment_coverage_pct": round((assessed / total) * 100, 1) if total > 0 else 0.0,
        "high_risk_count": high_risk,
        "critical_risk_count": critical_risk,
        "contracts_expiring_30d": expiring_30d,
        "contracts_expiring_90d": expiring_90d,
        "vendors_by_category": by_category,
    }


@router.get("/risk-matrix")
def risk_matrix(email: str = Depends(verify_token)):
    """Return all assessed vendors plotted on a likelihood x impact grid.

    Likelihood is derived from compliance + contract risk (how likely an incident is).
    Impact is derived from data sensitivity + AI dependency + concentration (how bad it would be).
    """
    matrix: dict[str, list] = {
        "low_likelihood_low_impact": [],
        "low_likelihood_high_impact": [],
        "high_likelihood_low_impact": [],
        "high_likelihood_high_impact": [],
    }

    for v in _vendors.values():
        ra = v.get("risk_assessment")
        if not ra:
            continue

        # Likelihood = average of compliance gap + contract risk
        likelihood = (ra["compliance_score"] + ra["contract_risk_score"]) / 2
        # Impact = average of data sensitivity + AI dependency + concentration
        impact = (
            ra["data_sensitivity_score"]
            + ra["ai_dependency_score"]
            + ra["concentration_risk_score"]
        ) / 3

        entry = {
            "id": v["id"],
            "name": v["name"],
            "likelihood": round(likelihood, 1),
            "impact": round(impact, 1),
            "overall_risk_score": ra["overall_risk_score"],
            "risk_level": ra["risk_level"],
        }

        high_likelihood = likelihood >= 50
        high_impact = impact >= 50

        if high_likelihood and high_impact:
            matrix["high_likelihood_high_impact"].append(entry)
        elif high_likelihood:
            matrix["high_likelihood_low_impact"].append(entry)
        elif high_impact:
            matrix["low_likelihood_high_impact"].append(entry)
        else:
            matrix["low_likelihood_low_impact"].append(entry)

    return {
        "matrix": matrix,
        "total_assessed": sum(len(q) for q in matrix.values()),
    }


@router.get("/{vendor_id}")
def get_vendor(vendor_id: str, email: str = Depends(verify_token)):
    """Get full vendor detail including risk assessment."""
    vendor = _vendors.get(vendor_id)
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")
    return _vendor_response(vendor)


@router.put("/{vendor_id}")
def update_vendor(vendor_id: str, body: VendorUpdate, email: str = Depends(verify_token)):
    """Update vendor information. Clears the existing risk assessment so it must be re-run."""
    vendor = _vendors.get(vendor_id)
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")

    update_data = body.model_dump(exclude_unset=True)

    # Convert date to ISO string for storage
    if "contract_end_date" in update_data and update_data["contract_end_date"] is not None:
        update_data["contract_end_date"] = update_data["contract_end_date"].isoformat()
    # Convert enum to string
    if "category" in update_data and update_data["category"] is not None:
        update_data["category"] = update_data["category"].value

    vendor.update(update_data)
    vendor["updated_at"] = datetime.utcnow().isoformat()

    # Invalidate previous assessment since data changed
    vendor["risk_assessment"] = None

    return _vendor_response(vendor)


@router.delete("/{vendor_id}", status_code=204)
def delete_vendor(vendor_id: str, email: str = Depends(verify_token)):
    """Remove a vendor from tracking."""
    if vendor_id not in _vendors:
        raise HTTPException(status_code=404, detail="Vendor not found")
    del _vendors[vendor_id]
    return None


@router.post("/{vendor_id}/assess")
def assess_vendor(vendor_id: str, email: str = Depends(verify_token)):
    """Run a deterministic risk assessment on a vendor.

    Scores five dimensions (0-100, higher = more risk):
    - data_sensitivity_score: based on types of data shared with vendor
    - ai_dependency_score: how critical the vendor's AI is to operations
    - compliance_score: inverse of certifications held (no certs = high risk)
    - contract_risk_score: based on contract end date proximity
    - concentration_risk_score: based on number of services from a single vendor

    Overall risk is a weighted average of all dimensions.
    """
    vendor = _vendors.get(vendor_id)
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")

    assessment = _assess_vendor(vendor, assessed_by=email)
    vendor["risk_assessment"] = assessment
    vendor["updated_at"] = datetime.utcnow().isoformat()

    return {
        "vendor_id": vendor_id,
        "vendor_name": vendor["name"],
        **assessment,
        "weights": _WEIGHTS,
    }


@router.post("/{vendor_id}/questionnaire")
def send_questionnaire(
    vendor_id: str,
    body: QuestionnaireRequest,
    email: str = Depends(verify_token),
):
    """Simulate sending a security questionnaire to a vendor.

    In production this would dispatch an email with a secure link.
    For now it records the request and updates the vendor status.
    """
    vendor = _vendors.get(vendor_id)
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")

    recipient = body.contact_email or vendor.get("contact_email")
    if not recipient:
        raise HTTPException(
            status_code=400,
            detail="No contact email provided. Set it on the vendor or in the request body.",
        )

    questionnaire_id = str(uuid.uuid4())
    vendor["questionnaire_status"] = QuestionnaireStatus.SENT.value
    vendor["updated_at"] = datetime.utcnow().isoformat()

    return {
        "questionnaire_id": questionnaire_id,
        "vendor_id": vendor_id,
        "vendor_name": vendor["name"],
        "recipient": recipient,
        "sections": body.sections,
        "status": QuestionnaireStatus.SENT.value,
        "sent_at": datetime.utcnow().isoformat(),
        "sent_by": email,
        "message": f"Security questionnaire dispatched to {recipient} (simulated)",
    }
