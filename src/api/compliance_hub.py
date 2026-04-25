"""Compliance Automation Hub — unified compliance programs, evidence, controls, policies, and vendor risk.

Ties together evidence collection, control mapping, policy generation, and audit readiness
into unified compliance programs spanning multiple frameworks (SOC 2, ISO 27001, NIST AI RMF, etc.).

Persistence: all data stored in PostgreSQL via SQLAlchemy (compliance_programs, compliance_policies,
compliance_audits tables). No in-memory state.
"""

import hashlib
import json
import random
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.models.compliance import ComplianceAudit, CompliancePolicy, ComplianceProgram
from src.models.database import get_db
from src.security.api_key_auth import AuthContext, verify_api_key_or_jwt
from src.security.auth import verify_token

router = APIRouter(prefix="/v1/compliance", tags=["Compliance Hub"])


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class PolicyStatus(str, Enum):
    DRAFT = "draft"
    REVIEW = "review"
    APPROVED = "approved"
    PUBLISHED = "published"


class AuditType(str, Enum):
    TYPE_I = "Type_I"
    TYPE_II = "Type_II"


class ControlStatus(str, Enum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    IMPLEMENTED = "implemented"
    VERIFIED = "verified"


class EvidenceStatus(str, Enum):
    MISSING = "missing"
    COLLECTED = "collected"
    REVIEWED = "reviewed"
    ACCEPTED = "accepted"


# ---------------------------------------------------------------------------
# Pydantic request / response models
# ---------------------------------------------------------------------------

class CreateProgramRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    frameworks: list[str] = Field(..., min_length=1)
    owner: str = Field(..., min_length=2, max_length=255)
    start_date: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
    target_audit_date: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")


class UpdateControlRequest(BaseModel):
    status: Optional[ControlStatus] = Field(default=None, description="New control status")
    owner: Optional[str] = Field(default=None, min_length=2, max_length=255, description="Control owner")
    last_reviewed: Optional[str] = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$", description="Last reviewed date (YYYY-MM-DD)")


class LinkEvidenceRequest(BaseModel):
    evidence_ref: str = Field(..., min_length=1, max_length=255, description="Evidence reference identifier")
    description: str = Field(..., min_length=1, max_length=2000, description="Description of the evidence")
    collected_by: str = Field(..., min_length=1, max_length=255, description="Who collected this evidence")


class ScheduleAuditRequest(BaseModel):
    auditor_firm: str = Field(..., min_length=2, max_length=255)
    proposed_date: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
    audit_type: AuditType
    notes: Optional[str] = Field(default=None, max_length=2000)


# ---------------------------------------------------------------------------
# Standards catalogue
# ---------------------------------------------------------------------------

STANDARDS_CATALOGUE: dict[str, dict] = {
    "SOC2": {
        "name": "SOC 2",
        "description": "Service Organization Control 2 — trust services criteria for security, availability, processing integrity, confidentiality, and privacy.",
        "control_count": 64,
        "categories": ["Security", "Availability", "Processing Integrity", "Confidentiality", "Privacy"],
    },
    "ISO27001": {
        "name": "ISO/IEC 27001:2022",
        "description": "International standard for information security management systems (ISMS) with 93 controls across 4 themes.",
        "control_count": 93,
        "categories": ["Organizational", "People", "Physical", "Technological"],
    },
    "NIST_AI_RMF": {
        "name": "NIST AI Risk Management Framework",
        "description": "Voluntary framework for managing risks to individuals, organizations, and society associated with AI.",
        "control_count": 42,
        "categories": ["Govern", "Map", "Measure", "Manage"],
    },
    "EU_AI_ACT": {
        "name": "EU AI Act",
        "description": "European regulation establishing harmonized rules on artificial intelligence, risk-based classification.",
        "control_count": 38,
        "categories": ["Risk Classification", "Transparency", "Data Governance", "Human Oversight", "Robustness"],
    },
    "HIPAA": {
        "name": "HIPAA Security Rule",
        "description": "US regulation protecting electronic health information through administrative, physical, and technical safeguards.",
        "control_count": 54,
        "categories": ["Administrative Safeguards", "Physical Safeguards", "Technical Safeguards"],
    },
    "GDPR": {
        "name": "General Data Protection Regulation",
        "description": "EU regulation on data protection and privacy, establishing data subject rights and processor obligations.",
        "control_count": 48,
        "categories": ["Lawfulness", "Data Subject Rights", "Data Protection", "International Transfers", "Governance"],
    },
    "NIST_CSF": {
        "name": "NIST Cybersecurity Framework 2.0",
        "description": "Framework for improving critical infrastructure cybersecurity across six core functions.",
        "control_count": 106,
        "categories": ["Govern", "Identify", "Protect", "Detect", "Respond", "Recover"],
    },
    "ISO42001": {
        "name": "ISO/IEC 42001:2023",
        "description": "International standard for AI management systems, specifying requirements for establishing and maintaining AIMS.",
        "control_count": 39,
        "categories": ["Leadership", "Planning", "Support", "Operation", "Performance Evaluation", "Improvement"],
    },
    "PCI_DSS": {
        "name": "PCI DSS v4.0",
        "description": "Payment Card Industry Data Security Standard for organizations that handle cardholder data.",
        "control_count": 78,
        "categories": ["Network Security", "Data Protection", "Vulnerability Management", "Access Control", "Monitoring", "Policy"],
    },
    "CCPA": {
        "name": "California Consumer Privacy Act",
        "description": "California state law granting consumers rights regarding personal information collected by businesses.",
        "control_count": 28,
        "categories": ["Consumer Rights", "Business Obligations", "Data Handling", "Opt-Out"],
    },
    "NIS2": {
        "name": "EU NIS2 Directive",
        "description": "EU directive on network and information security requiring risk management, incident reporting, and supply chain security for essential and important entities.",
        "control_count": 32,
        "categories": ["Risk Management", "Incident Reporting", "Supply Chain", "Business Continuity"],
    },
    "DORA": {
        "name": "EU Digital Operational Resilience Act",
        "description": "EU regulation ensuring financial entities can withstand ICT disruptions through risk management, incident management, resilience testing, and third-party oversight.",
        "control_count": 36,
        "categories": ["ICT Risk Management", "Incident Management", "Resilience Testing", "Third-Party Risk"],
    },
    "DSA": {
        "name": "EU Digital Services Act",
        "description": "EU regulation for digital services requiring algorithmic transparency, systemic risk assessment, and independent auditing for online platforms.",
        "control_count": 28,
        "categories": ["Algorithmic Transparency", "Content Moderation", "Risk Assessment", "Auditing"],
    },
    "DMA": {
        "name": "EU Digital Markets Act",
        "description": "EU regulation for digital gatekeepers requiring interoperability, data portability, profiling consent, and fair competition practices.",
        "control_count": 24,
        "categories": ["Interoperability", "Data Portability", "Fair Competition", "Profiling & Consent"],
    },
}


# ---------------------------------------------------------------------------
# Policy templates — used by generate-policies
# ---------------------------------------------------------------------------

POLICY_TEMPLATES: list[dict] = [
    {
        "title": "Information Security Policy",
        "summary": "Establishes the organization's commitment to protecting information assets through risk-based controls, incident management, and continuous improvement of the security posture.",
        "frameworks": ["SOC2", "ISO27001", "NIST_CSF"],
        "sections": ["Purpose", "Scope", "Roles & Responsibilities", "Risk Assessment", "Security Controls", "Incident Response", "Review Cycle"],
    },
    {
        "title": "Access Control Policy",
        "summary": "Defines requirements for identity management, authentication, authorization, and least-privilege access to systems, data, and AI models.",
        "frameworks": ["SOC2", "ISO27001", "NIST_CSF", "HIPAA"],
        "sections": ["User Provisioning", "Authentication Standards", "Role-Based Access", "Privileged Access", "Access Reviews", "Termination Procedures"],
    },
    {
        "title": "Data Classification Policy",
        "summary": "Provides a tiered classification scheme (Public, Internal, Confidential, Restricted) and mandates handling procedures for each level including AI training data.",
        "frameworks": ["ISO27001", "GDPR", "HIPAA", "CCPA"],
        "sections": ["Classification Tiers", "Labeling", "Handling Requirements", "AI Training Data", "Retention", "Disposal"],
    },
    {
        "title": "Incident Response Policy",
        "summary": "Outlines procedures for detecting, reporting, containing, and recovering from security incidents including AI system failures and data breaches.",
        "frameworks": ["SOC2", "ISO27001", "NIST_CSF", "HIPAA"],
        "sections": ["Detection", "Triage & Classification", "Containment", "Eradication", "Recovery", "Post-Incident Review", "Notification Requirements"],
    },
    {
        "title": "AI Governance Policy",
        "summary": "Establishes guardrails for AI development, deployment, and monitoring including bias testing, drift detection, human oversight, and model lifecycle management.",
        "frameworks": ["NIST_AI_RMF", "EU_AI_ACT", "ISO42001"],
        "sections": ["AI Risk Classification", "Model Registration", "Bias & Fairness Testing", "Drift Monitoring", "Human Oversight", "Model Decommissioning"],
    },
    {
        "title": "Acceptable Use Policy",
        "summary": "Defines acceptable and prohibited uses of organizational IT resources, AI tools, and data assets by employees, contractors, and automated agents.",
        "frameworks": ["SOC2", "ISO27001"],
        "sections": ["Scope", "Acceptable Use", "Prohibited Activities", "AI Tool Usage", "Monitoring", "Violations & Enforcement"],
    },
    {
        "title": "Change Management Policy",
        "summary": "Governs how changes to production systems, AI models, and infrastructure are requested, reviewed, tested, approved, and deployed.",
        "frameworks": ["SOC2", "ISO27001", "NIST_CSF"],
        "sections": ["Change Categories", "Request Process", "Impact Assessment", "Approval Workflow", "Testing Requirements", "Rollback Procedures", "Emergency Changes"],
    },
    {
        "title": "Business Continuity Policy",
        "summary": "Ensures critical business functions and AI-dependent processes can continue during disruptions through documented recovery plans and regular testing.",
        "frameworks": ["SOC2", "ISO27001", "NIST_CSF"],
        "sections": ["Business Impact Analysis", "Recovery Objectives", "Continuity Plans", "AI System Recovery", "Testing Schedule", "Plan Maintenance"],
    },
    {
        "title": "Vendor Management Policy",
        "summary": "Establishes due diligence, risk assessment, and ongoing monitoring requirements for third-party vendors including AI model providers and cloud services.",
        "frameworks": ["SOC2", "ISO27001", "NIST_AI_RMF"],
        "sections": ["Vendor Classification", "Due Diligence", "Risk Assessment", "Contract Requirements", "AI Vendor Addendum", "Ongoing Monitoring", "Termination"],
    },
    {
        "title": "Privacy Policy",
        "summary": "Documents how the organization collects, processes, stores, and shares personal data in compliance with applicable privacy regulations and AI transparency requirements.",
        "frameworks": ["GDPR", "CCPA", "HIPAA"],
        "sections": ["Data Collection", "Legal Basis", "Data Subject Rights", "AI Processing Transparency", "Data Sharing", "International Transfers", "Retention"],
    },
]


# ---------------------------------------------------------------------------
# Helpers: serialization between DB (JSON text) and Python dicts/lists
# ---------------------------------------------------------------------------

def _load_json(text: str | None) -> list | dict:
    """Safely parse a JSON text column back to Python."""
    if not text:
        return []
    return json.loads(text)


def _dump_json(obj) -> str:
    """Serialize a Python object to JSON string for storage."""
    return json.dumps(obj, default=str)


def _program_to_dict(prog: ComplianceProgram) -> dict:
    """Convert a ComplianceProgram ORM row to the dict format used by endpoints."""
    return {
        "id": prog.id,
        "name": prog.name,
        "frameworks": _load_json(prog.frameworks),
        "owner": prog.owner,
        "start_date": prog.start_date,
        "target_audit_date": prog.target_audit_date,
        "created_at": prog.created_at,
        "controls": _load_json(prog.controls),
    }


def _policy_to_dict(pol: CompliancePolicy) -> dict:
    """Convert a CompliancePolicy ORM row to the dict format used by endpoints."""
    return {
        "id": pol.id,
        "program_id": pol.program_id,
        "title": pol.title,
        "summary": pol.summary,
        "sections": _load_json(pol.sections),
        "applicable_frameworks": _load_json(pol.applicable_frameworks),
        "status": pol.status,
        "version": pol.version,
        "word_count": pol.word_count,
        "generated_by": pol.generated_by,
        "generated_at": pol.generated_at,
        "last_modified_by": pol.last_modified_by,
    }


def _audit_to_dict(aud: ComplianceAudit) -> dict:
    """Convert a ComplianceAudit ORM row to the dict format used by endpoints."""
    return {
        "id": aud.id,
        "program_id": aud.program_id,
        "auditor_firm": aud.auditor_firm,
        "proposed_date": aud.proposed_date,
        "audit_type": aud.audit_type,
        "notes": aud.notes,
        "status": aud.status,
        "readiness_at_scheduling": aud.readiness_at_scheduling,
        "scheduled_by": aud.scheduled_by,
        "scheduled_at": aud.scheduled_at,
    }


# ---------------------------------------------------------------------------
# Helpers: controls generation and progress calculation
# ---------------------------------------------------------------------------

def _generate_controls(frameworks: list[str]) -> list[dict]:
    """Generate a realistic set of controls mapped to the given frameworks."""
    controls = []
    control_num = 1
    for fw in frameworks:
        std = STANDARDS_CATALOGUE.get(fw)
        if not std:
            continue
        for cat in std["categories"]:
            num_controls = random.randint(3, 8)
            for i in range(num_controls):
                cid = f"{fw}-{cat[:3].upper()}-{control_num:03d}"
                statuses = list(ControlStatus)
                status = random.choice(statuses)
                evidence_count = random.randint(0, 4) if status != ControlStatus.NOT_STARTED else 0
                controls.append({
                    "id": cid,
                    "framework": fw,
                    "category": cat,
                    "title": f"{cat} control {i + 1}",
                    "status": status.value,
                    "evidence_count": evidence_count,
                    "evidence_required": random.randint(2, 5),
                    "owner": None,
                    "last_reviewed": None,
                })
                control_num += 1
    return controls


def _calculate_progress(controls: list[dict]) -> dict:
    """Derive progress metrics from a list of controls."""
    total = len(controls)
    if total == 0:
        return {"overall_pct": 0, "controls_total": 0, "implemented": 0, "verified": 0, "in_progress": 0, "not_started": 0, "evidence_collected": 0, "evidence_required": 0, "gaps": 0}
    implemented = sum(1 for c in controls if c["status"] in ("implemented", "verified"))
    verified = sum(1 for c in controls if c["status"] == "verified")
    in_progress = sum(1 for c in controls if c["status"] == "in_progress")
    not_started = sum(1 for c in controls if c["status"] == "not_started")
    evidence_collected = sum(c["evidence_count"] for c in controls)
    evidence_required = sum(c["evidence_required"] for c in controls)
    gaps = sum(1 for c in controls if c["status"] in ("not_started", "in_progress"))
    overall_pct = round((implemented / total) * 100, 1)
    return {
        "overall_pct": overall_pct,
        "controls_total": total,
        "implemented": implemented,
        "verified": verified,
        "in_progress": in_progress,
        "not_started": not_started,
        "evidence_collected": evidence_collected,
        "evidence_required": evidence_required,
        "gaps": gaps,
    }


def _ensure_demo_program(db: Session) -> None:
    """Seed a demo compliance program if the database is empty."""
    existing = db.query(ComplianceProgram).first()
    if existing:
        return

    pid = "demo-" + uuid4().hex[:8]
    frameworks = ["SOC2", "NIST_AI_RMF"]
    controls = _generate_controls(frameworks)

    # Make the demo program partially complete
    random.seed(42)
    for c in controls:
        roll = random.random()
        if roll < 0.35:
            c["status"] = ControlStatus.VERIFIED.value
            c["evidence_count"] = c["evidence_required"]
            c["last_reviewed"] = "2026-03-25"
        elif roll < 0.60:
            c["status"] = ControlStatus.IMPLEMENTED.value
            c["evidence_count"] = c["evidence_required"] - 1
        elif roll < 0.80:
            c["status"] = ControlStatus.IN_PROGRESS.value
            c["evidence_count"] = random.randint(1, 2)
        else:
            c["status"] = ControlStatus.NOT_STARTED.value
            c["evidence_count"] = 0
    random.seed()

    program = ComplianceProgram(
        id=pid,
        name="SOC 2 + NIST AI RMF Compliance Program",
        frameworks=_dump_json(frameworks),
        owner="ciso@company.com",
        start_date="2026-01-15",
        target_audit_date="2026-06-30",
        created_at="2026-01-15T09:00:00Z",
        controls=_dump_json(controls),
    )
    db.add(program)
    db.commit()


# ---------------------------------------------------------------------------
# Helper: org ownership check
# ---------------------------------------------------------------------------

def _verify_program_org(program: ComplianceProgram, auth: AuthContext) -> None:
    """Raise 404 if the program belongs to a different org. Allow if program has no org (legacy)."""
    if program.org_id is not None and auth.org_id is not None and program.org_id != auth.org_id:
        raise HTTPException(status_code=404, detail="Compliance program not found")


# ---------------------------------------------------------------------------
# 1. POST /programs — Create a compliance program
# ---------------------------------------------------------------------------

@router.post("/programs")
def create_program(req: CreateProgramRequest, auth: AuthContext = Depends(verify_api_key_or_jwt), db: Session = Depends(get_db)):
    """Create a new compliance program spanning one or more frameworks."""
    # Validate frameworks
    invalid = [f for f in req.frameworks if f not in STANDARDS_CATALOGUE]
    if invalid:
        supported = sorted(STANDARDS_CATALOGUE.keys())
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported frameworks: {invalid}. Supported: {supported}",
        )

    pid = "prog-" + uuid4().hex[:8]
    controls = _generate_controls(req.frameworks)
    # New programs start with all controls not_started
    for c in controls:
        c["status"] = ControlStatus.NOT_STARTED.value
        c["evidence_count"] = 0

    created_at = datetime.utcnow().isoformat() + "Z"

    program = ComplianceProgram(
        id=pid,
        name=req.name,
        frameworks=_dump_json(req.frameworks),
        owner=req.owner,
        start_date=req.start_date,
        target_audit_date=req.target_audit_date,
        created_at=created_at,
        controls=_dump_json(controls),
        org_id=auth.org_id,
    )
    db.add(program)
    db.commit()

    progress = _calculate_progress(controls)

    return {
        "id": pid,
        "name": req.name,
        "frameworks": req.frameworks,
        "owner": req.owner,
        "start_date": req.start_date,
        "target_audit_date": req.target_audit_date,
        "created_at": created_at,
        "controls_total": progress["controls_total"],
        "message": f"Compliance program created with {progress['controls_total']} controls across {len(req.frameworks)} framework(s).",
    }


# ---------------------------------------------------------------------------
# 2. GET /programs — List all programs with progress
# ---------------------------------------------------------------------------

@router.get("/programs")
def list_programs(auth: AuthContext = Depends(verify_api_key_or_jwt), db: Session = Depends(get_db)):
    """List all compliance programs with progress summaries."""
    _ensure_demo_program(db)

    query = db.query(ComplianceProgram)
    if auth.org_id is not None:
        query = query.filter(
            (ComplianceProgram.org_id == auth.org_id) | (ComplianceProgram.org_id.is_(None))
        )
    rows = query.all()
    results = []
    for row in rows:
        p = _program_to_dict(row)
        progress = _calculate_progress(p["controls"])
        results.append({
            "id": p["id"],
            "name": p["name"],
            "frameworks": p["frameworks"],
            "owner": p["owner"],
            "start_date": p["start_date"],
            "target_audit_date": p["target_audit_date"],
            "progress_pct": progress["overall_pct"],
            "controls_total": progress["controls_total"],
            "gaps_remaining": progress["gaps"],
            "created_at": p["created_at"],
        })
    return {"total": len(results), "programs": results}


# ---------------------------------------------------------------------------
# 3. GET /programs/{program_id} — Program detail
# ---------------------------------------------------------------------------

@router.get("/programs/{program_id}")
def get_program(program_id: str, auth: AuthContext = Depends(verify_api_key_or_jwt), db: Session = Depends(get_db)):
    """Get detailed program status: progress, controls, evidence, gaps, timeline."""
    _ensure_demo_program(db)

    row = db.query(ComplianceProgram).filter_by(id=program_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Compliance program not found")
    _verify_program_org(row, auth)

    program = _program_to_dict(row)
    controls = program["controls"]
    progress = _calculate_progress(controls)

    start = datetime.strptime(program["start_date"], "%Y-%m-%d")
    target = datetime.strptime(program["target_audit_date"], "%Y-%m-%d")
    today = datetime.utcnow()
    total_days = (target - start).days or 1
    elapsed_days = min((today - start).days, total_days)
    days_remaining = max((target - today).days, 0)
    time_elapsed_pct = round((elapsed_days / total_days) * 100, 1)

    # Framework breakdown
    fw_breakdown = {}
    for fw in program["frameworks"]:
        fw_controls = [c for c in controls if c["framework"] == fw]
        fw_breakdown[fw] = _calculate_progress(fw_controls)

    # Identify top gaps
    gap_controls = [c for c in controls if c["status"] in ("not_started", "in_progress")]
    gap_controls.sort(key=lambda c: (0 if c["status"] == "not_started" else 1, c["evidence_count"]))

    # Count policies linked to this program
    policy_count = db.query(CompliancePolicy).filter_by(program_id=program_id).count()

    # Count audits linked to this program
    audit_count = db.query(ComplianceAudit).filter_by(program_id=program_id).count()

    return {
        "id": program["id"],
        "name": program["name"],
        "frameworks": program["frameworks"],
        "owner": program["owner"],
        "start_date": program["start_date"],
        "target_audit_date": program["target_audit_date"],
        "progress": progress,
        "framework_breakdown": fw_breakdown,
        "timeline": {
            "total_days": total_days,
            "elapsed_days": elapsed_days,
            "days_remaining": days_remaining,
            "time_elapsed_pct": time_elapsed_pct,
            "on_track": progress["overall_pct"] >= time_elapsed_pct * 0.8,
        },
        "policies_generated": policy_count,
        "audits_scheduled": audit_count,
        "top_gaps": gap_controls[:10],
        "created_at": program["created_at"],
    }


# ---------------------------------------------------------------------------
# 3a. GET /programs/{program_id}/controls — List controls with filtering
# ---------------------------------------------------------------------------

@router.get("/programs/{program_id}/controls")
def list_controls(
    program_id: str,
    status: Optional[str] = Query(default=None, description="Filter by control status: not_started, in_progress, implemented, verified"),
    framework: Optional[str] = Query(default=None, description="Filter by framework ID (e.g. SOC2, ISO27001)"),
    auth: AuthContext = Depends(verify_api_key_or_jwt),
    db: Session = Depends(get_db),
):
    """List all controls for a compliance program with optional filtering by status and framework."""
    _ensure_demo_program(db)

    row = db.query(ComplianceProgram).filter_by(id=program_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Compliance program not found")
    _verify_program_org(row, auth)

    controls = _load_json(row.controls)

    # Validate status filter if provided
    if status:
        valid_statuses = [s.value for s in ControlStatus]
        if status not in valid_statuses:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status filter: {status}. Valid values: {valid_statuses}",
            )
        controls = [c for c in controls if c["status"] == status]

    # Validate framework filter if provided
    if framework:
        program_frameworks = _load_json(row.frameworks)
        if framework not in program_frameworks:
            raise HTTPException(
                status_code=400,
                detail=f"Framework '{framework}' is not part of this program. Program frameworks: {program_frameworks}",
            )
        controls = [c for c in controls if c["framework"] == framework]

    progress = _calculate_progress(controls)

    return {
        "program_id": program_id,
        "total": len(controls),
        "filters_applied": {
            "status": status,
            "framework": framework,
        },
        "progress": progress,
        "controls": controls,
    }


# ---------------------------------------------------------------------------
# 3b. PUT /programs/{program_id}/controls/{control_id} — Update control status
# ---------------------------------------------------------------------------

@router.put("/programs/{program_id}/controls/{control_id}")
def update_control(
    program_id: str,
    control_id: str,
    req: UpdateControlRequest,
    auth: AuthContext = Depends(verify_api_key_or_jwt),
    db: Session = Depends(get_db),
):
    """Update a control's status, owner, or last_reviewed date within a compliance program."""
    _ensure_demo_program(db)

    row = db.query(ComplianceProgram).filter_by(id=program_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Compliance program not found")
    _verify_program_org(row, auth)

    controls = _load_json(row.controls)

    # Find the target control
    target_idx = None
    for idx, c in enumerate(controls):
        if c["id"] == control_id:
            target_idx = idx
            break

    if target_idx is None:
        raise HTTPException(status_code=404, detail=f"Control '{control_id}' not found in program '{program_id}'")

    control = controls[target_idx]

    # Apply updates
    updated_fields = []
    if req.status is not None:
        control["status"] = req.status.value
        updated_fields.append("status")
    if req.owner is not None:
        control["owner"] = req.owner
        updated_fields.append("owner")
    if req.last_reviewed is not None:
        control["last_reviewed"] = req.last_reviewed
        updated_fields.append("last_reviewed")

    if not updated_fields:
        raise HTTPException(status_code=400, detail="No fields to update. Provide at least one of: status, owner, last_reviewed")

    controls[target_idx] = control

    # Persist back to DB
    row.controls = _dump_json(controls)
    db.commit()

    return {
        "program_id": program_id,
        "control": control,
        "updated_fields": updated_fields,
        "updated_by": auth.identity,
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }


# ---------------------------------------------------------------------------
# 3c. POST /programs/{program_id}/controls/{control_id}/evidence — Link evidence
# ---------------------------------------------------------------------------

@router.post("/programs/{program_id}/controls/{control_id}/evidence")
def link_evidence(
    program_id: str,
    control_id: str,
    req: LinkEvidenceRequest,
    auth: AuthContext = Depends(verify_api_key_or_jwt),
    db: Session = Depends(get_db),
):
    """Link evidence to a specific control, incrementing the control's evidence count."""
    _ensure_demo_program(db)

    row = db.query(ComplianceProgram).filter_by(id=program_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Compliance program not found")
    _verify_program_org(row, auth)

    controls = _load_json(row.controls)

    # Find the target control
    target_idx = None
    for idx, c in enumerate(controls):
        if c["id"] == control_id:
            target_idx = idx
            break

    if target_idx is None:
        raise HTTPException(status_code=404, detail=f"Control '{control_id}' not found in program '{program_id}'")

    control = controls[target_idx]

    # Increment evidence count
    control["evidence_count"] = control.get("evidence_count", 0) + 1
    controls[target_idx] = control

    # Persist back to DB
    row.controls = _dump_json(controls)
    db.commit()

    linked_at = datetime.utcnow().isoformat() + "Z"

    return {
        "program_id": program_id,
        "control": control,
        "evidence_linked": {
            "evidence_ref": req.evidence_ref,
            "description": req.description,
            "collected_by": req.collected_by,
            "linked_by": auth.identity,
            "linked_at": linked_at,
        },
        "message": f"Evidence '{req.evidence_ref}' linked to control '{control_id}'. Evidence count is now {control['evidence_count']}.",
    }


# ---------------------------------------------------------------------------
# 4. GET /programs/{program_id}/readiness — Audit readiness report
# ---------------------------------------------------------------------------

@router.get("/programs/{program_id}/readiness")
def get_readiness(program_id: str, auth: AuthContext = Depends(verify_api_key_or_jwt), db: Session = Depends(get_db)):
    """Generate an audit readiness report with framework-by-framework breakdown."""
    _ensure_demo_program(db)

    row = db.query(ComplianceProgram).filter_by(id=program_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Compliance program not found")
    _verify_program_org(row, auth)

    program = _program_to_dict(row)
    controls = program["controls"]
    progress = _calculate_progress(controls)

    # Framework breakdown with readiness scores
    fw_readiness = {}
    for fw in program["frameworks"]:
        fw_controls = [c for c in controls if c["framework"] == fw]
        fw_prog = _calculate_progress(fw_controls)
        evidence_coverage = round((fw_prog["evidence_collected"] / max(fw_prog["evidence_required"], 1)) * 100, 1)
        fw_readiness[fw] = {
            "standard": STANDARDS_CATALOGUE.get(fw, {}).get("name", fw),
            "controls_total": fw_prog["controls_total"],
            "controls_ready": fw_prog["implemented"] + fw_prog["verified"],
            "readiness_pct": fw_prog["overall_pct"],
            "evidence_coverage_pct": evidence_coverage,
            "gaps_remaining": fw_prog["gaps"],
            "verdict": "ready" if fw_prog["overall_pct"] >= 80 else "at_risk" if fw_prog["overall_pct"] >= 50 else "not_ready",
        }

    # Critical gaps: not_started controls
    critical_gaps = [
        {"control_id": c["id"], "framework": c["framework"], "category": c["category"], "title": c["title"]}
        for c in controls
        if c["status"] == "not_started"
    ]

    # Overall readiness
    overall_score = progress["overall_pct"]
    evidence_total_coverage = round((progress["evidence_collected"] / max(progress["evidence_required"], 1)) * 100, 1)

    # Check if policies exist for this program
    has_policies = db.query(CompliancePolicy).filter_by(program_id=program_id).first() is not None
    has_audits = db.query(ComplianceAudit).filter_by(program_id=program_id).first() is not None

    # Recommended actions
    actions = []
    if progress["not_started"] > 0:
        actions.append({
            "priority": "critical",
            "action": f"Address {progress['not_started']} controls that have not been started.",
            "impact": "Blocks audit readiness for affected frameworks.",
        })
    if evidence_total_coverage < 80:
        actions.append({
            "priority": "high",
            "action": f"Collect missing evidence — current coverage is {evidence_total_coverage}%. Target 100%.",
            "impact": "Auditors will flag insufficient evidence as a finding.",
        })
    if progress["in_progress"] > 5:
        actions.append({
            "priority": "medium",
            "action": f"Complete {progress['in_progress']} controls currently in progress.",
            "impact": "Reduces risk of audit delays.",
        })
    if not has_policies:
        actions.append({
            "priority": "high",
            "action": "Generate policy documents via POST /v1/compliance/programs/{id}/generate-policies.",
            "impact": "Auditors require documented policies for every control domain.",
        })
    if not has_audits:
        actions.append({
            "priority": "medium",
            "action": "Schedule an audit engagement via POST /v1/compliance/programs/{id}/schedule-audit.",
            "impact": "Lead time with audit firms is typically 4-8 weeks.",
        })

    return {
        "program_id": program_id,
        "program_name": program["name"],
        "overall_readiness_score": overall_score,
        "overall_verdict": "ready" if overall_score >= 80 else "at_risk" if overall_score >= 50 else "not_ready",
        "evidence_coverage_pct": evidence_total_coverage,
        "framework_readiness": fw_readiness,
        "critical_gaps": critical_gaps[:20],
        "critical_gap_count": len(critical_gaps),
        "recommended_actions": actions,
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }


# ---------------------------------------------------------------------------
# 5. POST /programs/{program_id}/generate-policies — Auto-generate policies
# ---------------------------------------------------------------------------

@router.post("/programs/{program_id}/generate-policies")
def generate_policies(program_id: str, auth: AuthContext = Depends(verify_api_key_or_jwt), db: Session = Depends(get_db)):
    """Auto-generate policy documents for the compliance program (simulated LLM generation)."""
    _ensure_demo_program(db)

    row = db.query(ComplianceProgram).filter_by(id=program_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Compliance program not found")
    _verify_program_org(row, auth)

    program = _program_to_dict(row)

    # Check if already generated
    existing = db.query(CompliancePolicy).filter_by(program_id=program_id).all()
    if existing:
        return {
            "message": f"Policies already generated for this program ({len(existing)} policies).",
            "policies": [
                {"id": p.id, "title": p.title, "status": p.status}
                for p in existing
            ],
        }

    generated = []
    for tmpl in POLICY_TEMPLATES:
        # Only generate policies relevant to the program's frameworks
        relevant = any(fw in program["frameworks"] for fw in tmpl["frameworks"])
        if not relevant:
            # Still include core policies even if framework doesn't match directly
            if tmpl["title"] not in ("Information Security Policy", "Acceptable Use Policy", "Change Management Policy", "Business Continuity Policy"):
                continue

        policy_id = "pol-" + uuid4().hex[:8]
        word_count = random.randint(2800, 6500)
        generated_at = datetime.utcnow().isoformat() + "Z"
        applicable_fws = [fw for fw in tmpl["frameworks"] if fw in program["frameworks"]] or tmpl["frameworks"][:1]

        policy = CompliancePolicy(
            id=policy_id,
            program_id=program_id,
            title=tmpl["title"],
            summary=tmpl["summary"],
            sections=_dump_json(tmpl["sections"]),
            applicable_frameworks=_dump_json(applicable_fws),
            status=PolicyStatus.DRAFT.value,
            version="1.0",
            word_count=word_count,
            generated_by="governlayer-ai",
            generated_at=generated_at,
            last_modified_by=auth.identity,
        )
        db.add(policy)
        generated.append({
            "id": policy_id,
            "title": tmpl["title"],
            "summary": tmpl["summary"],
            "sections": tmpl["sections"],
            "word_count": word_count,
            "status": PolicyStatus.DRAFT.value,
        })

    db.commit()

    return {
        "program_id": program_id,
        "policies_generated": len(generated),
        "policies": generated,
        "message": f"Generated {len(generated)} policy documents in draft status. Review and approve via the policies endpoint.",
    }


# ---------------------------------------------------------------------------
# 6. GET /policies — List all generated policies
# ---------------------------------------------------------------------------

@router.get("/policies")
def list_policies(
    status: Optional[str] = Query(default=None, description="Filter by status: draft, review, approved, published"),
    program_id: Optional[str] = Query(default=None, description="Filter by program ID"),
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    """List all generated compliance policies with status."""
    _ensure_demo_program(db)

    query = db.query(CompliancePolicy)
    if status:
        query = query.filter(CompliancePolicy.status == status)
    if program_id:
        query = query.filter(CompliancePolicy.program_id == program_id)

    rows = query.all()
    results = [_policy_to_dict(p) for p in rows]

    return {
        "total": len(results),
        "policies": [
            {
                "id": p["id"],
                "program_id": p["program_id"],
                "title": p["title"],
                "summary": p["summary"],
                "status": p["status"],
                "version": p["version"],
                "applicable_frameworks": p["applicable_frameworks"],
                "word_count": p["word_count"] or 0,
                "generated_at": p["generated_at"],
                "last_modified_by": p["last_modified_by"],
            }
            for p in results
        ],
    }


# ---------------------------------------------------------------------------
# 7. GET /policies/{policy_id} — Policy detail
# ---------------------------------------------------------------------------

@router.get("/policies/{policy_id}")
def get_policy(policy_id: str, email: str = Depends(verify_token), db: Session = Depends(get_db)):
    """Return full policy detail including sections content."""
    row = db.query(CompliancePolicy).filter_by(id=policy_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Policy not found")
    return _policy_to_dict(row)


# ---------------------------------------------------------------------------
# 8. PUT /policies/{policy_id} — Update policy status (lifecycle management)
# ---------------------------------------------------------------------------

# Valid status transitions: current_status -> set of allowed next statuses
_VALID_TRANSITIONS: dict[str, set[str]] = {
    "draft": {"review"},
    "review": {"approved", "draft"},
    "approved": {"published"},
    "published": set(),  # terminal state
}


class UpdatePolicyRequest(BaseModel):
    status: PolicyStatus


def _increment_version(version: str) -> str:
    """Increment the minor version component, e.g. '1.0' -> '1.1', '2.3' -> '2.4'."""
    parts = version.split(".")
    if len(parts) == 2:
        try:
            major, minor = int(parts[0]), int(parts[1])
            return f"{major}.{minor + 1}"
        except ValueError:
            pass
    return version


@router.put("/policies/{policy_id}")
def update_policy_status(
    policy_id: str,
    req: UpdatePolicyRequest,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    """Advance a policy through its lifecycle: draft -> review -> approved -> published.

    Valid transitions:
      - draft -> review
      - review -> approved
      - review -> draft  (sent back for revision)
      - approved -> published

    Version is incremented automatically on approval.
    """
    row = db.query(CompliancePolicy).filter_by(id=policy_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Policy not found")

    current_status = row.status
    new_status = req.status.value

    if new_status == current_status:
        raise HTTPException(
            status_code=400,
            detail=f"Policy is already in '{current_status}' status.",
        )

    allowed = _VALID_TRANSITIONS.get(current_status, set())
    if new_status not in allowed:
        allowed_list = sorted(allowed) if allowed else ["none (terminal state)"]
        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid status transition: '{current_status}' -> '{new_status}'. "
                f"Allowed transitions from '{current_status}': {allowed_list}."
            ),
        )

    # Increment version on approval
    if new_status == "approved":
        row.version = _increment_version(row.version)

    row.status = new_status
    row.last_modified_by = email

    db.commit()
    db.refresh(row)

    return _policy_to_dict(row)


# ---------------------------------------------------------------------------
# 9. POST /programs/{program_id}/schedule-audit — Schedule an audit
# ---------------------------------------------------------------------------

@router.post("/programs/{program_id}/schedule-audit")
def schedule_audit(program_id: str, req: ScheduleAuditRequest, auth: AuthContext = Depends(verify_api_key_or_jwt), db: Session = Depends(get_db)):
    """Schedule a formal audit engagement for the compliance program."""
    _ensure_demo_program(db)

    row = db.query(ComplianceProgram).filter_by(id=program_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Compliance program not found")
    _verify_program_org(row, auth)

    program = _program_to_dict(row)
    progress = _calculate_progress(program["controls"])

    audit_id = "aud-" + uuid4().hex[:8]
    scheduled_at = datetime.utcnow().isoformat() + "Z"

    audit = ComplianceAudit(
        id=audit_id,
        program_id=program_id,
        auditor_firm=req.auditor_firm,
        proposed_date=req.proposed_date,
        audit_type=req.audit_type.value,
        notes=req.notes,
        status="scheduled",
        readiness_at_scheduling=progress["overall_pct"],
        scheduled_by=auth.identity,
        scheduled_at=scheduled_at,
    )
    db.add(audit)
    db.commit()

    # Warn if readiness is low
    warnings = []
    if progress["overall_pct"] < 70:
        warnings.append(f"Current readiness is {progress['overall_pct']}%. Recommend reaching 80%+ before audit.")
    if progress["not_started"] > 0:
        warnings.append(f"{progress['not_started']} controls have not been started.")

    return {
        "audit_id": audit_id,
        "program_id": program_id,
        "auditor_firm": req.auditor_firm,
        "proposed_date": req.proposed_date,
        "audit_type": req.audit_type.value,
        "status": "scheduled",
        "readiness_at_scheduling_pct": progress["overall_pct"],
        "warnings": warnings,
        "scheduled_at": scheduled_at,
    }


# ---------------------------------------------------------------------------
# 10. GET /programs/{program_id}/controls — List controls with filtering
# ---------------------------------------------------------------------------

@router.get("/programs/{program_id}/controls")
def list_controls(
    program_id: str,
    status: Optional[str] = Query(default=None, description="Filter by status: not_started, in_progress, implemented, verified"),
    framework: Optional[str] = Query(default=None, description="Filter by framework ID"),
    category: Optional[str] = Query(default=None, description="Filter by category"),
    auth: AuthContext = Depends(verify_api_key_or_jwt),
    db: Session = Depends(get_db),
):
    """List all controls for a compliance program with optional filtering."""
    _ensure_demo_program(db)

    row = db.query(ComplianceProgram).filter_by(id=program_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Compliance program not found")
    _verify_program_org(row, auth)

    controls = _load_json(row.controls)

    if status:
        controls = [c for c in controls if c["status"] == status]
    if framework:
        controls = [c for c in controls if c["framework"] == framework]
    if category:
        controls = [c for c in controls if c["category"].lower() == category.lower()]

    progress = _calculate_progress(controls)

    return {
        "program_id": program_id,
        "total": len(controls),
        "progress": progress,
        "controls": controls,
    }


# ---------------------------------------------------------------------------
# 11. PUT /programs/{program_id}/controls/{control_id} — Update control status
# ---------------------------------------------------------------------------

@router.put("/programs/{program_id}/controls/{control_id}")
def update_control(
    program_id: str,
    control_id: str,
    req: UpdateControlRequest,
    auth: AuthContext = Depends(verify_api_key_or_jwt),
    db: Session = Depends(get_db),
):
    """Update a control's status, owner, or review date for remediation tracking."""
    row = db.query(ComplianceProgram).filter_by(id=program_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Compliance program not found")
    _verify_program_org(row, auth)

    controls = _load_json(row.controls)
    target = None
    for c in controls:
        if c["id"] == control_id:
            target = c
            break

    if not target:
        raise HTTPException(status_code=404, detail=f"Control '{control_id}' not found in program")

    if req.status is not None:
        target["status"] = req.status.value
    if req.owner is not None:
        target["owner"] = req.owner
    if req.last_reviewed is not None:
        target["last_reviewed"] = req.last_reviewed

    row.controls = _dump_json(controls)
    db.commit()

    return {
        "program_id": program_id,
        "control": target,
        "message": f"Control '{control_id}' updated successfully.",
    }


# ---------------------------------------------------------------------------
# 12. POST /programs/{program_id}/controls/{control_id}/evidence — Link evidence
# ---------------------------------------------------------------------------

@router.post("/programs/{program_id}/controls/{control_id}/evidence")
def link_evidence(
    program_id: str,
    control_id: str,
    req: LinkEvidenceRequest,
    auth: AuthContext = Depends(verify_api_key_or_jwt),
    db: Session = Depends(get_db),
):
    """Link evidence to a specific control. Increments evidence count and stores reference."""
    row = db.query(ComplianceProgram).filter_by(id=program_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Compliance program not found")
    _verify_program_org(row, auth)

    controls = _load_json(row.controls)
    target = None
    for c in controls:
        if c["id"] == control_id:
            target = c
            break

    if not target:
        raise HTTPException(status_code=404, detail=f"Control '{control_id}' not found in program")

    if "evidence" not in target:
        target["evidence"] = []
    evidence_id = f"EV-{control_id}-{len(target['evidence']) + 1:02d}"
    evidence_entry = {
        "id": evidence_id,
        "ref": req.evidence_ref,
        "description": req.description,
        "collected_by": req.collected_by,
        "collected_at": datetime.utcnow().isoformat() + "Z",
        "status": EvidenceStatus.COLLECTED.value,
    }
    target["evidence"].append(evidence_entry)
    target["evidence_count"] = len(target["evidence"])

    row.controls = _dump_json(controls)
    db.commit()

    return {
        "program_id": program_id,
        "control_id": control_id,
        "evidence": evidence_entry,
        "total_evidence": target["evidence_count"],
        "evidence_required": target["evidence_required"],
        "message": f"Evidence '{evidence_id}' linked to control '{control_id}'.",
    }


# ---------------------------------------------------------------------------
# 13. GET /standards — List supported compliance standards
# ---------------------------------------------------------------------------

@router.get("/standards")
def list_standards(email: str = Depends(verify_token)):
    """List all supported compliance standards with control counts and descriptions."""
    standards = []
    for key, std in STANDARDS_CATALOGUE.items():
        standards.append({
            "id": key,
            "name": std["name"],
            "description": std["description"],
            "control_count": std["control_count"],
            "categories": std["categories"],
        })
    return {"total": len(standards), "standards": standards}


# ---------------------------------------------------------------------------
# 9. GET /programs/{program_id}/export — Export compliance package
# ---------------------------------------------------------------------------

@router.get("/programs/{program_id}/export")
def export_program(program_id: str, auth: AuthContext = Depends(verify_api_key_or_jwt), db: Session = Depends(get_db)):
    """Export the full compliance package as JSON (evidence, controls, policies, gaps)."""
    _ensure_demo_program(db)

    row = db.query(ComplianceProgram).filter_by(id=program_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Compliance program not found")
    _verify_program_org(row, auth)

    program = _program_to_dict(row)
    controls = program["controls"]
    progress = _calculate_progress(controls)

    # Gather policies
    policy_rows = db.query(CompliancePolicy).filter_by(program_id=program_id).all()
    program_policies = [
        {
            "id": p.id,
            "title": p.title,
            "summary": p.summary,
            "sections": _load_json(p.sections),
            "status": p.status,
            "version": p.version,
            "applicable_frameworks": _load_json(p.applicable_frameworks),
            "word_count": p.word_count or 0,
        }
        for p in policy_rows
    ]

    # Gather audits
    audit_rows = db.query(ComplianceAudit).filter_by(program_id=program_id).all()
    program_audits = [_audit_to_dict(a) for a in audit_rows]

    # Gaps
    gaps = [
        {"control_id": c["id"], "framework": c["framework"], "category": c["category"], "title": c["title"], "status": c["status"], "evidence_count": c["evidence_count"], "evidence_required": c["evidence_required"]}
        for c in controls
        if c["status"] in ("not_started", "in_progress")
    ]

    # Evidence summary
    evidence_items = []
    for c in controls:
        if c["evidence_count"] > 0:
            for i in range(c["evidence_count"]):
                evidence_items.append({
                    "control_id": c["id"],
                    "framework": c["framework"],
                    "evidence_ref": f"EV-{c['id']}-{i+1:02d}",
                    "status": "collected",
                })

    # Package hash for integrity
    package_str = f"{program_id}:{len(controls)}:{len(program_policies)}:{progress['overall_pct']}"
    package_hash = hashlib.sha256(package_str.encode()).hexdigest()

    return {
        "export_format": "governlayer-compliance-package-v1",
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "exported_by": auth.identity,
        "package_hash": package_hash,
        "program": {
            "id": program["id"],
            "name": program["name"],
            "frameworks": program["frameworks"],
            "owner": program["owner"],
            "start_date": program["start_date"],
            "target_audit_date": program["target_audit_date"],
            "created_at": program["created_at"],
        },
        "progress": progress,
        "controls": controls,
        "policies": program_policies,
        "evidence": evidence_items,
        "gaps": gaps,
        "audits": program_audits,
        "summary": {
            "controls_total": progress["controls_total"],
            "controls_ready": progress["implemented"] + progress["verified"],
            "policies_count": len(program_policies),
            "evidence_items": len(evidence_items),
            "gaps_count": len(gaps),
            "audits_scheduled": len(program_audits),
            "overall_readiness_pct": progress["overall_pct"],
        },
    }


# ---------------------------------------------------------------------------
# 10. GET /benchmarks — Industry benchmarks
# ---------------------------------------------------------------------------

@router.get("/benchmarks")
def get_benchmarks(email: str = Depends(verify_token), db: Session = Depends(get_db)):
    """Industry benchmarks: compare organizational compliance scores against median."""
    _ensure_demo_program(db)

    # Calculate org-level stats from all programs
    all_controls = []
    rows = db.query(ComplianceProgram).all()
    programs = [_program_to_dict(r) for r in rows]
    for p in programs:
        all_controls.extend(p["controls"])

    org_progress = _calculate_progress(all_controls) if all_controls else {"overall_pct": 0, "controls_total": 0}

    # Simulated industry benchmarks (realistic medians)
    benchmarks = {
        "SOC2": {
            "industry_median_readiness_pct": 68.0,
            "top_quartile_pct": 89.0,
            "avg_time_to_compliance_days": 180,
            "avg_controls_automated_pct": 42.0,
            "common_gaps": ["Access reviews", "Change management", "Vendor oversight", "Incident response testing"],
        },
        "ISO27001": {
            "industry_median_readiness_pct": 55.0,
            "top_quartile_pct": 82.0,
            "avg_time_to_compliance_days": 240,
            "avg_controls_automated_pct": 35.0,
            "common_gaps": ["Risk assessment methodology", "Physical security", "Supplier management", "Internal audit program"],
        },
        "NIST_AI_RMF": {
            "industry_median_readiness_pct": 32.0,
            "top_quartile_pct": 61.0,
            "avg_time_to_compliance_days": 150,
            "avg_controls_automated_pct": 28.0,
            "common_gaps": ["AI impact assessment", "Bias testing", "Model documentation", "Human oversight protocols"],
        },
        "EU_AI_ACT": {
            "industry_median_readiness_pct": 22.0,
            "top_quartile_pct": 48.0,
            "avg_time_to_compliance_days": 300,
            "avg_controls_automated_pct": 18.0,
            "common_gaps": ["Risk classification", "Conformity assessment", "Post-market monitoring", "Transparency obligations"],
        },
        "HIPAA": {
            "industry_median_readiness_pct": 72.0,
            "top_quartile_pct": 91.0,
            "avg_time_to_compliance_days": 160,
            "avg_controls_automated_pct": 48.0,
            "common_gaps": ["Risk analysis updates", "Workforce training", "Business associate agreements", "Contingency planning"],
        },
        "GDPR": {
            "industry_median_readiness_pct": 58.0,
            "top_quartile_pct": 80.0,
            "avg_time_to_compliance_days": 200,
            "avg_controls_automated_pct": 38.0,
            "common_gaps": ["Data processing records", "DPIA completion", "Cross-border transfer mechanisms", "Consent management"],
        },
    }

    # Per-framework comparison for this org
    org_vs_industry = {}
    for p in programs:
        for fw in p["frameworks"]:
            if fw in benchmarks:
                fw_controls = [c for c in p["controls"] if c["framework"] == fw]
                fw_progress = _calculate_progress(fw_controls)
                median = benchmarks[fw]["industry_median_readiness_pct"]
                delta = round(fw_progress["overall_pct"] - median, 1)
                org_vs_industry[fw] = {
                    "org_readiness_pct": fw_progress["overall_pct"],
                    "industry_median_pct": median,
                    "top_quartile_pct": benchmarks[fw]["top_quartile_pct"],
                    "delta_vs_median": delta,
                    "position": "above_median" if delta > 0 else "below_median" if delta < 0 else "at_median",
                }

    return {
        "org_overall_readiness_pct": org_progress["overall_pct"],
        "org_total_controls": org_progress["controls_total"],
        "programs_count": len(programs),
        "org_vs_industry": org_vs_industry,
        "industry_benchmarks": benchmarks,
        "data_source": "GovernLayer aggregated benchmark data (anonymized)",
        "last_updated": "2026-03-31",
    }
