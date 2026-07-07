"""Data Residency Controls.

Per-org policy declaring which regions are permitted for processing and
storage of decision payloads. Provides:

  - Org-level residency config (allowed regions, denied regions, fallback action).
  - Pre-flight check endpoint: given a target region + payload classification,
    return permit | deny | redact-and-permit, with reasoning.
  - Violation log: any pre-flight check that resulted in deny is recorded for
    later inspection (drives the residency violation alerting story).
  - Region inventory: built-in catalogue of supported regions, sovereignty
    metadata (which jurisdiction governs data placed there) so the frontend
    can build dropdowns from one source of truth.

Endpoints:
  GET  /residency/regions                  - Catalogue of supported regions
  GET  /residency/policy/{org_id}          - Active policy for an org
  POST /residency/policy/{org_id}          - Set policy
  POST /residency/check                    - Pre-flight check
  GET  /residency/violations               - Recent violations (paginated)
  GET  /residency/stats
"""

from __future__ import annotations

import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/residency", tags=["residency"])


# ---------------------------------------------------------------------------
# Region catalogue
# ---------------------------------------------------------------------------

REGIONS: dict[str, dict] = {
    "us-east-1": {"jurisdiction": "US", "country": "United States", "sovereignty": "US Federal", "data_protection": "varies by state (CCPA/CDPA/VCDPA)"},
    "us-west-2": {"jurisdiction": "US", "country": "United States", "sovereignty": "US Federal", "data_protection": "varies by state"},
    "us-gov-east-1": {"jurisdiction": "US-GOV", "country": "United States", "sovereignty": "US Federal Govt", "data_protection": "FedRAMP, ITAR"},
    "eu-west-1": {"jurisdiction": "EU", "country": "Ireland", "sovereignty": "EU/Ireland", "data_protection": "GDPR, EU AI Act"},
    "eu-central-1": {"jurisdiction": "EU", "country": "Germany", "sovereignty": "EU/Germany", "data_protection": "GDPR, BDSG, EU AI Act"},
    "eu-north-1": {"jurisdiction": "EU", "country": "Sweden", "sovereignty": "EU/Sweden", "data_protection": "GDPR, EU AI Act"},
    "uk-south-1": {"jurisdiction": "UK", "country": "United Kingdom", "sovereignty": "UK", "data_protection": "UK GDPR, DPA 2018"},
    "ca-central-1": {"jurisdiction": "CA", "country": "Canada", "sovereignty": "Canadian Federal", "data_protection": "PIPEDA, CPPA (pending)"},
    "ap-south-1": {"jurisdiction": "IN", "country": "India", "sovereignty": "India", "data_protection": "DPDP Act 2023"},
    "ap-southeast-2": {"jurisdiction": "AU", "country": "Australia", "sovereignty": "Australia", "data_protection": "Privacy Act 1988"},
    "ap-northeast-1": {"jurisdiction": "JP", "country": "Japan", "sovereignty": "Japan", "data_protection": "APPI"},
    "af-south-1": {"jurisdiction": "ZA", "country": "South Africa", "sovereignty": "South Africa", "data_protection": "POPIA"},
    "me-south-1": {"jurisdiction": "AE", "country": "United Arab Emirates", "sovereignty": "UAE", "data_protection": "PDPL"},
    "sa-east-1": {"jurisdiction": "BR", "country": "Brazil", "sovereignty": "Brazil", "data_protection": "LGPD"},
}


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class ResidencyPolicy(BaseModel):
    org_id: str
    allowed_regions: list[str] = Field(default_factory=list)
    denied_regions: list[str] = Field(default_factory=list)
    default_region: Optional[str] = None
    fallback_action: str = Field(
        default="deny",
        description="When target region is not allowed: deny | redact_and_permit | route_to_default",
    )
    require_encryption_at_rest: bool = True
    require_separate_kms_per_jurisdiction: bool = True
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CheckRequest(BaseModel):
    org_id: str
    target_region: str
    payload_classification: str = Field(
        default="standard",
        description="standard | restricted | pii | phi | pci",
    )


class CheckResponse(BaseModel):
    decision: str = Field(..., description="permit | deny | redact_and_permit | route_to_default")
    target_region: str
    routed_to: Optional[str] = None
    reason: str
    policy_violations: list[str] = []
    jurisdiction: Optional[str] = None
    timestamp: datetime


class Violation(BaseModel):
    violation_id: str
    org_id: str
    target_region: str
    payload_classification: str
    reason: str
    timestamp: datetime


# ---------------------------------------------------------------------------
# In-memory stores
# ---------------------------------------------------------------------------

_policies: dict[str, ResidencyPolicy] = {}
_violations: deque[Violation] = deque(maxlen=10_000)
_counters: dict[str, int] = {"checks": 0, "permits": 0, "denies": 0, "redacted": 0, "rerouted": 0}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/regions")
def list_regions() -> dict:
    return {
        "regions": [{"region": r, **meta} for r, meta in REGIONS.items()],
        "count": len(REGIONS),
        "jurisdictions": sorted({meta["jurisdiction"] for meta in REGIONS.values()}),
    }


@router.get("/policy/{org_id}", response_model=ResidencyPolicy)
def get_policy(org_id: str) -> ResidencyPolicy:
    if org_id not in _policies:
        return ResidencyPolicy(org_id=org_id, allowed_regions=list(REGIONS.keys()))
    return _policies[org_id]


@router.post("/policy/{org_id}", response_model=ResidencyPolicy)
def set_policy(org_id: str, policy: ResidencyPolicy) -> ResidencyPolicy:
    if policy.org_id != org_id:
        raise HTTPException(status_code=400, detail="org_id in path and body must match")
    for region in policy.allowed_regions + policy.denied_regions:
        if region not in REGIONS:
            raise HTTPException(status_code=400, detail=f"Unknown region: {region}")
    if policy.default_region and policy.default_region not in REGIONS:
        raise HTTPException(status_code=400, detail=f"Unknown default region: {policy.default_region}")
    if policy.fallback_action not in {"deny", "redact_and_permit", "route_to_default"}:
        raise HTTPException(status_code=400, detail=f"Invalid fallback_action: {policy.fallback_action}")
    policy.updated_at = datetime.now(timezone.utc)
    _policies[org_id] = policy
    return policy


@router.post("/check", response_model=CheckResponse)
def check(req: CheckRequest) -> CheckResponse:
    _counters["checks"] += 1
    if req.target_region not in REGIONS:
        raise HTTPException(status_code=400, detail=f"Unknown target region: {req.target_region}")
    jurisdiction = REGIONS[req.target_region]["jurisdiction"]
    policy = _policies.get(req.org_id)

    if policy is None:
        _counters["permits"] += 1
        return CheckResponse(
            decision="permit",
            target_region=req.target_region,
            reason="No residency policy configured for org — defaults to permit.",
            jurisdiction=jurisdiction,
            timestamp=datetime.now(timezone.utc),
        )

    violations: list[str] = []

    if req.target_region in policy.denied_regions:
        violations.append(f"Region {req.target_region} is explicitly denied")
    if policy.allowed_regions and req.target_region not in policy.allowed_regions:
        violations.append(f"Region {req.target_region} is not in the allowed list")

    # PHI/PCI restrictions: never permit across mismatched jurisdictions
    if req.payload_classification in {"phi", "pci"} and policy.default_region:
        default_jur = REGIONS[policy.default_region]["jurisdiction"]
        if default_jur != jurisdiction:
            violations.append(
                f"Classification '{req.payload_classification}' must remain in jurisdiction "
                f"{default_jur}; target is {jurisdiction}"
            )

    if not violations:
        _counters["permits"] += 1
        return CheckResponse(
            decision="permit",
            target_region=req.target_region,
            reason="Target region permitted by org policy.",
            jurisdiction=jurisdiction,
            timestamp=datetime.now(timezone.utc),
        )

    # Violation — record and apply fallback action
    v = Violation(
        violation_id=f"vio_{uuid.uuid4().hex[:12]}",
        org_id=req.org_id,
        target_region=req.target_region,
        payload_classification=req.payload_classification,
        reason="; ".join(violations),
        timestamp=datetime.now(timezone.utc),
    )
    _violations.append(v)

    if policy.fallback_action == "deny":
        _counters["denies"] += 1
        return CheckResponse(
            decision="deny",
            target_region=req.target_region,
            reason=v.reason,
            policy_violations=violations,
            jurisdiction=jurisdiction,
            timestamp=datetime.now(timezone.utc),
        )

    if policy.fallback_action == "redact_and_permit":
        _counters["redacted"] += 1
        return CheckResponse(
            decision="redact_and_permit",
            target_region=req.target_region,
            reason=v.reason + " — falling back to redact-and-permit.",
            policy_violations=violations,
            jurisdiction=jurisdiction,
            timestamp=datetime.now(timezone.utc),
        )

    # route_to_default
    if not policy.default_region:
        _counters["denies"] += 1
        return CheckResponse(
            decision="deny",
            target_region=req.target_region,
            reason=v.reason + " — fallback is route_to_default but no default_region set.",
            policy_violations=violations,
            jurisdiction=jurisdiction,
            timestamp=datetime.now(timezone.utc),
        )

    _counters["rerouted"] += 1
    return CheckResponse(
        decision="route_to_default",
        target_region=req.target_region,
        routed_to=policy.default_region,
        reason=v.reason + f" — rerouted to {policy.default_region}.",
        policy_violations=violations,
        jurisdiction=jurisdiction,
        timestamp=datetime.now(timezone.utc),
    )


@router.get("/violations")
def list_violations(org_id: Optional[str] = None, limit: int = 100) -> dict:
    items = list(_violations)
    if org_id:
        items = [v for v in items if v.org_id == org_id]
    items = items[-limit:][::-1]  # most recent first
    return {"violations": items, "count": len(items)}


@router.get("/stats")
def stats() -> dict:
    return {
        "counters": dict(_counters),
        "policies_configured": len(_policies),
        "violations_recorded": len(_violations),
    }
