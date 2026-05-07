"""Workspace API — team management, activity log, notifications, evidence upload."""

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.models.database import MutationLog, get_db
from src.models.tenant import OrgMembership, Organization
from src.security.auth import verify_token

router = APIRouter(prefix="/v1/workspace", tags=["Workspace"])


# ─── Team Management ─────────────────────────────────────────────────


class TeamInvite(BaseModel):
    email: str
    role: str = "member"  # owner, admin, member, viewer


@router.get("/team")
def list_team(email: str = Depends(verify_token), db: Session = Depends(get_db)):
    """List all team members in the user's organization."""
    membership = db.query(OrgMembership).filter(OrgMembership.user_email == email).first()
    if not membership:
        return {"members": [], "org": None}

    org = db.query(Organization).filter(Organization.id == membership.org_id).first()
    members = db.query(OrgMembership).filter(OrgMembership.org_id == membership.org_id).all()

    return {
        "org": {"id": org.id, "name": org.name, "slug": org.slug, "plan": org.plan} if org else None,
        "members": [
            {
                "email": m.user_email,
                "role": m.role,
                "joined": m.created_at.isoformat() if m.created_at else None,
            }
            for m in members
        ],
        "total": len(members),
    }


@router.post("/team/invite")
def invite_member(data: TeamInvite, email: str = Depends(verify_token), db: Session = Depends(get_db)):
    """Invite a team member to the organization."""
    membership = db.query(OrgMembership).filter(OrgMembership.user_email == email).first()
    if not membership:
        raise HTTPException(status_code=403, detail="You must belong to an organization")
    if membership.role not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Only owners and admins can invite members")
    if data.role not in ("owner", "admin", "member", "viewer"):
        raise HTTPException(status_code=400, detail="Invalid role")

    existing = (
        db.query(OrgMembership)
        .filter(OrgMembership.user_email == data.email, OrgMembership.org_id == membership.org_id)
        .first()
    )
    if existing:
        raise HTTPException(status_code=409, detail="User is already a member")

    new_member = OrgMembership(
        user_email=data.email,
        org_id=membership.org_id,
        role=data.role,
    )
    db.add(new_member)
    db.commit()

    # Send invite email
    from src.notifications.email import send_email
    from src.notifications.templates import BRAND_HEADER, BRAND_FOOTER
    org = db.query(Organization).filter(Organization.id == membership.org_id).first()
    org_name = org.name if org else "GovernLayer"
    subject = f"You've been invited to {org_name} on GovernLayer"
    html = BRAND_HEADER + f"""
<div style="background:#111;border:1px solid #222;border-radius:8px;padding:24px">
<h2 style="color:#fff;margin:0 0 12px;font-size:18px">Team Invitation</h2>
<p style="color:#aaa;line-height:1.6">
<strong style="color:#fff">{email}</strong> invited you to join <strong style="color:#00ff88">{org_name}</strong> as a <strong style="color:#fff">{data.role}</strong>.
</p>
<div style="text-align:center;margin:24px 0">
<a href="https://www.governlayer.ai/login" style="display:inline-block;background:#00ff88;color:#000;padding:12px 32px;border-radius:6px;text-decoration:none;font-weight:700;font-size:14px">Accept Invitation</a>
</div>
</div>
""" + BRAND_FOOTER
    send_email(data.email, subject, html)

    return {"invited": data.email, "role": data.role, "org": org_name}


@router.delete("/team/{member_email}")
def remove_member(member_email: str, email: str = Depends(verify_token), db: Session = Depends(get_db)):
    """Remove a team member from the organization."""
    membership = db.query(OrgMembership).filter(OrgMembership.user_email == email).first()
    if not membership or membership.role not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Only owners/admins can remove members")
    if member_email == email:
        raise HTTPException(status_code=400, detail="Cannot remove yourself")

    target = (
        db.query(OrgMembership)
        .filter(OrgMembership.user_email == member_email, OrgMembership.org_id == membership.org_id)
        .first()
    )
    if not target:
        raise HTTPException(status_code=404, detail="Member not found")
    db.delete(target)
    db.commit()
    return {"removed": member_email}


# ─── Activity Log ─────────────────────────────────────────────────────


@router.get("/activity")
def get_activity_log(
    limit: int = 50,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    """Get recent activity log (mutation history) for the workspace."""
    entries = (
        db.query(MutationLog)
        .order_by(MutationLog.created_at.desc())
        .limit(limit)
        .all()
    )
    return {
        "total": len(entries),
        "entries": [
            {
                "id": e.id,
                "actor": e.actor,
                "action": e.action,
                "resource_type": e.resource_type,
                "resource_id": e.resource_id,
                "details": e.details,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in entries
        ],
    }


# ─── Email Notifications ──────────────────────────────────────────────


class DigestRequest(BaseModel):
    to: Optional[str] = None


@router.post("/send-digest")
def send_weekly_digest(data: DigestRequest, email: str = Depends(verify_token), db: Session = Depends(get_db)):
    """Send a compliance digest email to the user or specified address."""
    recipient = data.to or email

    from src.reports.generator import generate_soc2_report, generate_gdpr_report
    from src.notifications.email import send_email
    from src.notifications.templates import BRAND_HEADER, BRAND_FOOTER

    try:
        soc2 = generate_soc2_report(system_name="organization", context={})
        gdpr = generate_gdpr_report(system_name="organization", context={})
        soc2_score = soc2.get("compliance_score", 0)
        gdpr_score = gdpr.get("compliance_score", 0)
    except Exception:
        soc2_score = 0
        gdpr_score = 0

    subject = f"GovernLayer Weekly Digest — {datetime.now(timezone.utc).strftime('%b %d, %Y')}"
    html = BRAND_HEADER + f"""
<div style="background:#111;border:1px solid #222;border-radius:8px;padding:24px">
<h2 style="color:#fff;margin:0 0 16px;font-size:18px">Weekly Compliance Digest</h2>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:20px;">
  <div style="background:#0a0a1a;border:1px solid #1a1a2e;border-radius:6px;padding:16px;text-align:center;">
    <div style="font-size:28px;font-weight:700;color:{'#10b981' if soc2_score >= 70 else '#f59e0b'}">{soc2_score}%</div>
    <div style="color:#888;font-size:13px;">SOC 2</div>
  </div>
  <div style="background:#0a0a1a;border:1px solid #1a1a2e;border-radius:6px;padding:16px;text-align:center;">
    <div style="font-size:28px;font-weight:700;color:{'#10b981' if gdpr_score >= 70 else '#f59e0b'}">{gdpr_score}%</div>
    <div style="color:#888;font-size:13px;">GDPR</div>
  </div>
</div>
<div style="text-align:center;margin:20px 0">
<a href="https://www.governlayer.ai/workspace" style="display:inline-block;background:#00ff88;color:#000;padding:12px 32px;border-radius:6px;text-decoration:none;font-weight:700;font-size:14px">Open Dashboard</a>
</div>
</div>
""" + BRAND_FOOTER

    success = send_email(recipient, subject, html)
    return {"sent": success, "to": recipient}


# ─── Evidence Upload ──────────────────────────────────────────────────

# Store evidence files in memory for MVP (production: S3/GCS)
_evidence_store: dict = {}


@router.post("/evidence/upload")
async def upload_evidence(
    file: UploadFile = File(...),
    control_id: str = "general",
    framework: str = "SOC_2",
    email: str = Depends(verify_token),
):
    """Upload an evidence file (screenshot, CSV, PDF, etc.)."""
    contents = await file.read()
    if len(contents) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 10MB)")

    evidence_id = f"ev_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}_{file.filename}"
    _evidence_store[evidence_id] = {
        "id": evidence_id,
        "filename": file.filename,
        "content_type": file.content_type,
        "size": len(contents),
        "control_id": control_id,
        "framework": framework,
        "uploaded_by": email,
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
    }

    return {
        "id": evidence_id,
        "filename": file.filename,
        "size": len(contents),
        "control_id": control_id,
        "framework": framework,
    }


@router.get("/evidence")
def list_evidence(email: str = Depends(verify_token)):
    """List all uploaded evidence files."""
    return {
        "total": len(_evidence_store),
        "evidence": list(_evidence_store.values()),
    }


# ─── Onboarding Status ───────────────────────────────────────────────


@router.get("/onboarding")
def get_onboarding_progress(email: str = Depends(verify_token), db: Session = Depends(get_db)):
    """Get detailed onboarding progress for the workspace setup wizard."""
    from src.models.tenant import ApiKey

    membership = db.query(OrgMembership).filter(OrgMembership.user_email == email).first()
    has_org = membership is not None

    has_api_key = False
    has_team = False
    org_info = None
    if membership:
        org = db.query(Organization).filter(Organization.id == membership.org_id).first()
        org_info = {"name": org.name, "slug": org.slug, "plan": org.plan} if org else None
        has_api_key = db.query(ApiKey).filter(ApiKey.org_id == membership.org_id, ApiKey.is_active == True).count() > 0
        has_team = db.query(OrgMembership).filter(OrgMembership.org_id == membership.org_id).count() > 1

    has_frameworks = True  # Always true after framework selector
    has_scan = db.query(MutationLog).filter(
        MutationLog.actor == email,
        MutationLog.resource_type.in_(["governance_decision", "risk_score", "quick_scan"]),
    ).count() > 0

    steps = [
        {"key": "account", "label": "Create account", "done": True},
        {"key": "org", "label": "Set up organization", "done": has_org},
        {"key": "frameworks", "label": "Select compliance frameworks", "done": has_frameworks},
        {"key": "integration", "label": "Connect an integration", "done": has_api_key},
        {"key": "scan", "label": "Run your first scan", "done": has_scan},
        {"key": "team", "label": "Invite team members", "done": has_team},
    ]

    completed = sum(1 for s in steps if s["done"])
    return {
        "steps": steps,
        "completed": completed,
        "total": len(steps),
        "pct": round(completed / len(steps) * 100),
        "org": org_info,
        "email": email,
    }
