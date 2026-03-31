"""Continuous Control Monitoring API — automated compliance control checks.

Closes the gap vs Vanta's automated control monitoring with AI-specific controls
that Vanta does not cover (shadow AI, drift, consensus, ledger integrity).
"""

import random
import uuid
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from src.security.auth import verify_token

router = APIRouter(prefix="/v1/controls", tags=["Control Monitoring"])


# ---------------------------------------------------------------------------
# Enums & Pydantic models
# ---------------------------------------------------------------------------

class ControlStatus(str, Enum):
    PASSING = "passing"
    FAILING = "failing"
    WARNING = "warning"
    NOT_CONFIGURED = "not_configured"


class ControlCategory(str, Enum):
    ACCESS_CONTROL = "Access Control"
    DATA_PROTECTION = "Data Protection"
    NETWORK_SECURITY = "Network Security"
    INCIDENT_RESPONSE = "Incident Response"
    CHANGE_MANAGEMENT = "Change Management"
    AI_GOVERNANCE = "AI Governance"
    ENCRYPTION = "Encryption"
    LOGGING_MONITORING = "Logging & Monitoring"


class ControlOut(BaseModel):
    id: str
    name: str
    category: str
    description: str
    status: ControlStatus
    last_checked: Optional[str] = None
    evidence_count: int = 0
    frameworks: list[str] = Field(default_factory=list)


class ControlDetail(ControlOut):
    check_history: list[dict] = Field(default_factory=list)


class CheckResult(BaseModel):
    control_id: str
    control_name: str
    status: ControlStatus
    checked_at: str
    message: str


class AlertRuleCreate(BaseModel):
    control_id: str
    condition: str = Field(default="fails", description="Trigger condition: fails | warning | any_change")
    notify: str = Field(..., description="Notification target: email address or webhook URL")


class AlertRuleOut(BaseModel):
    id: str
    control_id: str
    control_name: str
    condition: str
    notify: str
    created_at: str
    triggered_count: int = 0


# ---------------------------------------------------------------------------
# In-memory stores
# ---------------------------------------------------------------------------

_controls: dict[str, dict] = {}
_check_history: list[dict] = []
_alert_rules: list[dict] = []


def _now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _seed_controls() -> None:
    """Pre-populate 30 controls across 8 categories + 6 AI-specific controls."""
    if _controls:
        return

    definitions = [
        # Access Control
        ("AC-01", "MFA enforcement", ControlCategory.ACCESS_CONTROL,
         "Multi-factor authentication enabled for all user accounts",
         ["SOC2", "ISO27001", "NIST_CSF"], ControlStatus.PASSING),
        ("AC-02", "Least-privilege access", ControlCategory.ACCESS_CONTROL,
         "Role-based access control with minimum required permissions",
         ["SOC2", "ISO27001", "NIST_CSF", "NIST_AI_RMF"], ControlStatus.PASSING),
        ("AC-03", "Access review cadence", ControlCategory.ACCESS_CONTROL,
         "Quarterly review of all user access rights and privileges",
         ["SOC2", "ISO27001"], ControlStatus.WARNING),
        ("AC-04", "SSO integration", ControlCategory.ACCESS_CONTROL,
         "Single sign-on enabled via SAML/OIDC for all production systems",
         ["SOC2", "ISO27001"], ControlStatus.PASSING),

        # Data Protection
        ("DP-01", "Data classification policy", ControlCategory.DATA_PROTECTION,
         "All data assets classified by sensitivity level with handling procedures",
         ["SOC2", "ISO27001", "GDPR", "CCPA"], ControlStatus.PASSING),
        ("DP-02", "PII inventory maintained", ControlCategory.DATA_PROTECTION,
         "Complete inventory of personally identifiable information with data maps",
         ["GDPR", "CCPA", "SOC2"], ControlStatus.WARNING),
        ("DP-03", "Data retention policy enforced", ControlCategory.DATA_PROTECTION,
         "Automated enforcement of data retention and deletion schedules",
         ["GDPR", "CCPA", "SOC2", "ISO27001"], ControlStatus.PASSING),
        ("DP-04", "Backup integrity verification", ControlCategory.DATA_PROTECTION,
         "Regular backup testing and integrity verification procedures",
         ["SOC2", "ISO27001", "NIST_CSF"], ControlStatus.PASSING),

        # Network Security
        ("NS-01", "Firewall rules reviewed", ControlCategory.NETWORK_SECURITY,
         "Firewall and security group rules reviewed quarterly for least privilege",
         ["SOC2", "ISO27001", "NIST_CSF", "CIS_CONTROLS"], ControlStatus.PASSING),
        ("NS-02", "Intrusion detection active", ControlCategory.NETWORK_SECURITY,
         "IDS/IPS deployed and alerting on suspicious network activity",
         ["SOC2", "ISO27001", "NIST_CSF", "CIS_CONTROLS"], ControlStatus.PASSING),
        ("NS-03", "Vulnerability scanning", ControlCategory.NETWORK_SECURITY,
         "Automated vulnerability scanning of all internet-facing assets weekly",
         ["SOC2", "ISO27001", "NIST_CSF", "CIS_CONTROLS"], ControlStatus.WARNING),
        ("NS-04", "DDoS protection enabled", ControlCategory.NETWORK_SECURITY,
         "Distributed denial-of-service mitigation active on all public endpoints",
         ["SOC2", "NIST_CSF"], ControlStatus.PASSING),

        # Incident Response
        ("IR-01", "Incident response plan documented", ControlCategory.INCIDENT_RESPONSE,
         "Comprehensive incident response plan with defined roles and procedures",
         ["SOC2", "ISO27001", "NIST_CSF", "NIS2"], ControlStatus.PASSING),
        ("IR-02", "Incident response tested", ControlCategory.INCIDENT_RESPONSE,
         "Tabletop exercises or simulations conducted at least annually",
         ["SOC2", "ISO27001", "NIS2"], ControlStatus.FAILING),
        ("IR-03", "Breach notification process", ControlCategory.INCIDENT_RESPONSE,
         "Documented process meeting 72-hour notification requirements",
         ["GDPR", "NIS2", "CCPA"], ControlStatus.PASSING),

        # Change Management
        ("CM-01", "Change approval workflow", ControlCategory.CHANGE_MANAGEMENT,
         "All production changes require peer review and approval before deployment",
         ["SOC2", "ISO27001", "ITIL"], ControlStatus.PASSING),
        ("CM-02", "Rollback capability", ControlCategory.CHANGE_MANAGEMENT,
         "All deployments have tested rollback procedures within 15 minutes",
         ["SOC2", "ISO27001", "ITIL"], ControlStatus.PASSING),
        ("CM-03", "Infrastructure as code", ControlCategory.CHANGE_MANAGEMENT,
         "All infrastructure defined in version-controlled code with drift detection",
         ["SOC2", "NIST_CSF"], ControlStatus.WARNING),
        ("CM-04", "Separation of environments", ControlCategory.CHANGE_MANAGEMENT,
         "Production, staging, and development environments fully isolated",
         ["SOC2", "ISO27001"], ControlStatus.PASSING),

        # Encryption
        ("EN-01", "Encryption at rest", ControlCategory.ENCRYPTION,
         "All data at rest encrypted with AES-256 or equivalent",
         ["SOC2", "ISO27001", "GDPR", "HIPAA"], ControlStatus.PASSING),
        ("EN-02", "Encryption in transit", ControlCategory.ENCRYPTION,
         "TLS 1.2+ enforced on all external and internal communications",
         ["SOC2", "ISO27001", "GDPR", "HIPAA", "NIST_CSF"], ControlStatus.PASSING),
        ("EN-03", "Key management procedure", ControlCategory.ENCRYPTION,
         "Cryptographic keys rotated on schedule with documented custody procedures",
         ["SOC2", "ISO27001", "NIST_CSF"], ControlStatus.WARNING),

        # Logging & Monitoring
        ("LM-01", "Centralized log aggregation", ControlCategory.LOGGING_MONITORING,
         "All system and application logs forwarded to centralized SIEM",
         ["SOC2", "ISO27001", "NIST_CSF", "CIS_CONTROLS"], ControlStatus.PASSING),
        ("LM-02", "Audit log tamper protection", ControlCategory.LOGGING_MONITORING,
         "Audit logs stored immutably with integrity verification",
         ["SOC2", "ISO27001", "NIST_CSF"], ControlStatus.PASSING),
        ("LM-03", "Alerting on anomalies", ControlCategory.LOGGING_MONITORING,
         "Automated alerting configured for security-relevant anomalies",
         ["SOC2", "ISO27001", "NIST_CSF", "CIS_CONTROLS"], ControlStatus.PASSING),

        # AI Governance  (GovernLayer-specific -- Vanta does not have these)
        ("AI-GOV-01", "Model registry completeness", ControlCategory.AI_GOVERNANCE,
         "All production AI/ML models registered in the governance registry with owner, version, and risk tier",
         ["NIST_AI_RMF", "EU_AI_ACT", "ISO_42001", "OECD_AI"], ControlStatus.WARNING),
        ("AI-GOV-02", "Shadow AI detection enabled", ControlCategory.AI_GOVERNANCE,
         "Automated scanning for unregistered AI/ML model usage across the organization",
         ["NIST_AI_RMF", "EU_AI_ACT", "ISO_42001"], ControlStatus.NOT_CONFIGURED),
        ("AI-GOV-03", "Drift monitoring active", ControlCategory.AI_GOVERNANCE,
         "Continuous behavioral drift detection running on all production AI agents",
         ["NIST_AI_RMF", "EU_AI_ACT", "ISO_42001", "OECD_AI"], ControlStatus.PASSING),
        ("AI-GOV-04", "Consensus validation for critical decisions", ControlCategory.AI_GOVERNANCE,
         "Critical AI decisions validated through multi-LLM consensus (voting, chain-of-verification, or adversarial debate)",
         ["NIST_AI_RMF", "EU_AI_ACT", "ISO_42001"], ControlStatus.PASSING),
        ("AI-GOV-05", "Audit ledger integrity verification", ControlCategory.AI_GOVERNANCE,
         "Hash-chained audit ledger verified for integrity on a continuous basis",
         ["NIST_AI_RMF", "SOC2", "ISO27001", "ISO_42001"], ControlStatus.PASSING),
        ("AI-GOV-06", "Agent risk assessment up to date", ControlCategory.AI_GOVERNANCE,
         "All AI agents have a current risk assessment scored within the last 30 days",
         ["NIST_AI_RMF", "EU_AI_ACT", "ISO_42001", "OECD_AI"], ControlStatus.WARNING),
    ]

    base_time = datetime.utcnow() - timedelta(hours=2)
    for idx, (cid, name, category, desc, frameworks, status) in enumerate(definitions):
        checked_at = (base_time + timedelta(minutes=idx * 3)).isoformat() + "Z"
        _controls[cid] = {
            "id": cid,
            "name": name,
            "category": category.value,
            "description": desc,
            "status": status.value,
            "last_checked": checked_at,
            "evidence_count": random.randint(1, 12),
            "frameworks": frameworks,
            "check_history": [
                {
                    "checked_at": checked_at,
                    "status": status.value,
                    "message": f"Initial check: {status.value}",
                }
            ],
        }


# Ensure controls are seeded on module load
_seed_controls()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_single_check(control: dict) -> dict:
    """Simulate running a control check and return the result."""
    # Weighted random: controls that were passing tend to stay passing
    current = control["status"]
    if current == ControlStatus.NOT_CONFIGURED.value:
        new_status = ControlStatus.NOT_CONFIGURED.value
        message = "Control not yet configured -- manual setup required"
    else:
        roll = random.random()
        if current == ControlStatus.PASSING.value:
            if roll < 0.85:
                new_status = ControlStatus.PASSING.value
                message = "All checks passed successfully"
            elif roll < 0.95:
                new_status = ControlStatus.WARNING.value
                message = "Minor configuration drift detected"
            else:
                new_status = ControlStatus.FAILING.value
                message = "Check failed -- remediation required"
        elif current == ControlStatus.WARNING.value:
            if roll < 0.50:
                new_status = ControlStatus.PASSING.value
                message = "Issue resolved -- all checks passing"
            elif roll < 0.85:
                new_status = ControlStatus.WARNING.value
                message = "Warning persists -- review recommended"
            else:
                new_status = ControlStatus.FAILING.value
                message = "Degraded to failure -- immediate action required"
        else:  # FAILING
            if roll < 0.30:
                new_status = ControlStatus.PASSING.value
                message = "Remediation successful -- control now passing"
            elif roll < 0.50:
                new_status = ControlStatus.WARNING.value
                message = "Partial remediation -- still needs attention"
            else:
                new_status = ControlStatus.FAILING.value
                message = "Still failing -- remediation incomplete"

    now = _now_iso()
    control["status"] = new_status
    control["last_checked"] = now

    entry = {"checked_at": now, "status": new_status, "message": message}
    control["check_history"].append(entry)

    # Keep history bounded
    if len(control["check_history"]) > 100:
        control["check_history"] = control["check_history"][-100:]

    return {
        "control_id": control["id"],
        "control_name": control["name"],
        "status": new_status,
        "checked_at": now,
        "message": message,
    }


def _compliance_score_for_framework(framework: str) -> float:
    """Calculate compliance percentage for a framework."""
    mapped = [c for c in _controls.values() if framework in c["frameworks"]]
    if not mapped:
        return 0.0
    passing = sum(1 for c in mapped if c["status"] == ControlStatus.PASSING.value)
    return round((passing / len(mapped)) * 100, 1)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("", response_model=list[ControlOut])
def list_controls(
    category: Optional[str] = Query(None, description="Filter by category"),
    status: Optional[str] = Query(None, description="Filter by status"),
    email: str = Depends(verify_token),
):
    """List all controls with current status, optionally filtered by category or status."""
    _seed_controls()
    controls = list(_controls.values())
    if category:
        controls = [c for c in controls if c["category"].lower() == category.lower()]
    if status:
        controls = [c for c in controls if c["status"] == status]
    return [
        {
            "id": c["id"],
            "name": c["name"],
            "category": c["category"],
            "description": c["description"],
            "status": c["status"],
            "last_checked": c["last_checked"],
            "evidence_count": c["evidence_count"],
            "frameworks": c["frameworks"],
        }
        for c in controls
    ]


@router.get("/dashboard")
def control_dashboard(email: str = Depends(verify_token)):
    """Dashboard summary: totals, compliance scores by framework, 7-day trend."""
    _seed_controls()
    all_controls = list(_controls.values())
    total = len(all_controls)
    passing = sum(1 for c in all_controls if c["status"] == ControlStatus.PASSING.value)
    failing = sum(1 for c in all_controls if c["status"] == ControlStatus.FAILING.value)
    warnings = sum(1 for c in all_controls if c["status"] == ControlStatus.WARNING.value)
    not_configured = sum(1 for c in all_controls if c["status"] == ControlStatus.NOT_CONFIGURED.value)

    # Gather all frameworks referenced across controls
    all_frameworks: set[str] = set()
    for c in all_controls:
        all_frameworks.update(c["frameworks"])

    framework_scores = {
        fw: _compliance_score_for_framework(fw) for fw in sorted(all_frameworks)
    }

    overall_score = round((passing / total) * 100, 1) if total else 0.0

    # Simulated 7-day trend (passing count per day)
    today = datetime.utcnow().date()
    trend = []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        # Slight variation around current passing count
        simulated_passing = max(0, min(total, passing + random.randint(-2, 2)))
        trend.append({
            "date": day.isoformat(),
            "passing": simulated_passing,
            "total": total,
            "score": round((simulated_passing / total) * 100, 1) if total else 0.0,
        })

    return {
        "total_controls": total,
        "passing": passing,
        "failing": failing,
        "warnings": warnings,
        "not_configured": not_configured,
        "overall_score": overall_score,
        "framework_scores": framework_scores,
        "trend_7d": trend,
        "checked_at": _now_iso(),
    }


@router.get("/history")
def control_history(
    control_id: Optional[str] = Query(None, description="Filter by control ID"),
    limit: int = Query(100, ge=1, le=500),
    email: str = Depends(verify_token),
):
    """Control check history (timestamped results), optionally filtered by control."""
    _seed_controls()
    if control_id:
        control = _controls.get(control_id)
        if not control:
            raise HTTPException(status_code=404, detail=f"Control {control_id} not found")
        entries = [
            {"control_id": control_id, "control_name": control["name"], **h}
            for h in reversed(control["check_history"])
        ]
    else:
        entries = []
        for c in _controls.values():
            for h in c["check_history"]:
                entries.append({"control_id": c["id"], "control_name": c["name"], **h})
        entries.sort(key=lambda e: e["checked_at"], reverse=True)

    return {"total": len(entries), "results": entries[:limit]}


@router.get("/gaps")
def gap_analysis(email: str = Depends(verify_token)):
    """Gap analysis: controls required by enabled frameworks that are failing or not configured."""
    _seed_controls()
    gaps = []
    for c in _controls.values():
        if c["status"] in (ControlStatus.FAILING.value, ControlStatus.NOT_CONFIGURED.value):
            gaps.append({
                "control_id": c["id"],
                "control_name": c["name"],
                "category": c["category"],
                "status": c["status"],
                "frameworks_affected": c["frameworks"],
                "remediation_priority": "critical" if c["status"] == ControlStatus.FAILING.value else "high",
                "description": c["description"],
            })

    # Sort: failing before not_configured, then alphabetical
    priority_order = {ControlStatus.FAILING.value: 0, ControlStatus.NOT_CONFIGURED.value: 1}
    gaps.sort(key=lambda g: (priority_order.get(g["status"], 2), g["control_id"]))

    # Count affected frameworks
    affected_frameworks: dict[str, int] = {}
    for g in gaps:
        for fw in g["frameworks_affected"]:
            affected_frameworks[fw] = affected_frameworks.get(fw, 0) + 1

    return {
        "total_gaps": len(gaps),
        "affected_frameworks": affected_frameworks,
        "gaps": gaps,
        "analyzed_at": _now_iso(),
    }


@router.get("/alerts")
def list_alerts(email: str = Depends(verify_token)):
    """List all configured alert rules."""
    return {"total": len(_alert_rules), "alerts": _alert_rules}


@router.post("/alerts")
def create_alert(rule: AlertRuleCreate, email: str = Depends(verify_token)):
    """Configure an alert rule for a control."""
    _seed_controls()
    if rule.control_id not in _controls:
        raise HTTPException(status_code=404, detail=f"Control {rule.control_id} not found")

    valid_conditions = ("fails", "warning", "any_change")
    if rule.condition not in valid_conditions:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid condition. Must be one of: {valid_conditions}",
        )

    alert = {
        "id": str(uuid.uuid4()),
        "control_id": rule.control_id,
        "control_name": _controls[rule.control_id]["name"],
        "condition": rule.condition,
        "notify": rule.notify,
        "created_at": _now_iso(),
        "triggered_count": 0,
    }
    _alert_rules.append(alert)
    return alert


@router.post("/check")
def run_all_checks(email: str = Depends(verify_token)):
    """Run all control checks (simulated). Returns pass/fail for each control."""
    _seed_controls()
    results = []
    for control in _controls.values():
        result = _run_single_check(control)
        results.append(result)

    passing = sum(1 for r in results if r["status"] == ControlStatus.PASSING.value)
    failing = sum(1 for r in results if r["status"] == ControlStatus.FAILING.value)
    warnings = sum(1 for r in results if r["status"] == ControlStatus.WARNING.value)

    return {
        "total_checked": len(results),
        "passing": passing,
        "failing": failing,
        "warnings": warnings,
        "results": results,
        "checked_at": _now_iso(),
    }


@router.get("/frameworks/{framework}")
def controls_by_framework(framework: str, email: str = Depends(verify_token)):
    """Get all controls mapped to a specific compliance framework."""
    _seed_controls()
    # Normalize: accept case-insensitive input
    framework_upper = framework.upper().replace("-", "_")

    mapped = [
        {
            "id": c["id"],
            "name": c["name"],
            "category": c["category"],
            "description": c["description"],
            "status": c["status"],
            "last_checked": c["last_checked"],
            "evidence_count": c["evidence_count"],
            "frameworks": c["frameworks"],
        }
        for c in _controls.values()
        if framework_upper in [fw.upper().replace("-", "_") for fw in c["frameworks"]]
    ]

    if not mapped:
        raise HTTPException(
            status_code=404,
            detail=f"No controls mapped to framework '{framework}'. "
                   f"Available: {sorted({fw for c in _controls.values() for fw in c['frameworks']})}",
        )

    passing = sum(1 for c in mapped if c["status"] == ControlStatus.PASSING.value)
    total = len(mapped)

    return {
        "framework": framework,
        "total_controls": total,
        "passing": passing,
        "compliance_score": round((passing / total) * 100, 1) if total else 0.0,
        "controls": mapped,
    }


@router.get("/{control_id}")
def get_control(control_id: str, email: str = Depends(verify_token)):
    """Get control detail with full check history."""
    _seed_controls()
    control = _controls.get(control_id)
    if not control:
        raise HTTPException(status_code=404, detail=f"Control {control_id} not found")
    return {
        "id": control["id"],
        "name": control["name"],
        "category": control["category"],
        "description": control["description"],
        "status": control["status"],
        "last_checked": control["last_checked"],
        "evidence_count": control["evidence_count"],
        "frameworks": control["frameworks"],
        "check_history": list(reversed(control["check_history"])),
    }


@router.post("/{control_id}/check")
def run_single_control_check(control_id: str, email: str = Depends(verify_token)):
    """Run a check on a single control."""
    _seed_controls()
    control = _controls.get(control_id)
    if not control:
        raise HTTPException(status_code=404, detail=f"Control {control_id} not found")
    return _run_single_check(control)
