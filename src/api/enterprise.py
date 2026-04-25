"""Enterprise API — org management, API key provisioning, usage, webhooks.

This is the self-service portal for enterprise customers.
"""

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.models.database import get_db, MutationLog
from src.models.tenant import ApiKey, OrgMembership, Organization, UsageRecord, Webhook, generate_api_key, verify_org_access
from src.security.auth import verify_token

router = APIRouter(prefix="/v1/enterprise", tags=["enterprise"])


# --- Schemas ---

class CreateOrgRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    slug: str = Field(..., min_length=2, max_length=100, pattern=r"^[a-z0-9-]+$")
    plan: str = Field(default="free", pattern=r"^(free|starter|pro|enterprise)$")


class CreateApiKeyRequest(BaseModel):
    name: str = Field(default="default", max_length=255)
    scopes: str = Field(default="govern,audit,risk,scan")
    expires_in_days: int | None = Field(default=None, ge=1, le=365)


class CreateWebhookRequest(BaseModel):
    url: str = Field(..., max_length=2048)
    events: str = Field(default="governance.decision,audit.complete")


# --- Org Management ---

@router.post("/orgs")
def create_org(req: CreateOrgRequest, email: str = Depends(verify_token), db: Session = Depends(get_db)):
    """Create a new organization (tenant)."""
    existing = db.query(Organization).filter(Organization.slug == req.slug).first()
    if existing:
        raise HTTPException(status_code=409, detail="Organization slug already taken")
    org = Organization(name=req.name, slug=req.slug, plan=req.plan)
    db.add(org)
    db.flush()  # Get org.id before committing
    membership = OrgMembership(user_email=email, org_id=org.id, role="owner")
    db.add(membership)
    db.commit()
    db.refresh(org)
    return {
        "id": org.id,
        "name": org.name,
        "slug": org.slug,
        "plan": org.plan,
        "created_at": org.created_at.isoformat(),
        "message": "Organization created. Generate an API key to start integrating.",
    }


@router.get("/orgs/{slug}")
def get_org(slug: str, email: str = Depends(verify_token), db: Session = Depends(get_db)):
    org = verify_org_access(email, slug, "viewer", db)
    key_count = db.query(ApiKey).filter(ApiKey.org_id == org.id, ApiKey.is_active.is_(True)).count()
    return {
        "id": org.id, "name": org.name, "slug": org.slug,
        "plan": org.plan, "is_active": org.is_active,
        "active_api_keys": key_count, "created_at": org.created_at.isoformat(),
    }


# --- API Key Management ---

@router.post("/orgs/{slug}/api-keys")
def create_api_key(slug: str, req: CreateApiKeyRequest, email: str = Depends(verify_token),
                   db: Session = Depends(get_db)):
    """Generate a new API key for the organization. The full key is only shown once."""
    org = verify_org_access(email, slug, "admin", db)

    full_key, prefix, key_hash = generate_api_key()
    expires_at = None
    if req.expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=req.expires_in_days)

    api_key = ApiKey(
        org_id=org.id, name=req.name, key_prefix=prefix,
        key_hash=key_hash, scopes=req.scopes, expires_at=expires_at,
    )
    db.add(api_key)
    db.commit()

    # Notify the user that a new API key was provisioned
    try:
        from src.email.service import send_api_key_created
        send_api_key_created(email, prefix)
    except Exception:
        pass  # Don't block key creation if email fails

    return {
        "api_key": full_key,  # Only shown once!
        "prefix": prefix,
        "name": req.name,
        "scopes": req.scopes.split(","),
        "expires_at": expires_at.isoformat() if expires_at else None,
        "warning": "Save this key now. It cannot be retrieved again.",
        "usage": {
            "header": "Authorization: Bearer " + full_key,
            "example": f"curl -H 'Authorization: Bearer {full_key}' https://governlayer.ai/v1/govern",
        },
    }


@router.get("/orgs/{slug}/api-keys")
def list_api_keys(slug: str, email: str = Depends(verify_token), db: Session = Depends(get_db)):
    org = verify_org_access(email, slug, "member", db)
    keys = db.query(ApiKey).filter(ApiKey.org_id == org.id).all()
    return {
        "keys": [
            {
                "id": k.id, "name": k.name, "prefix": k.key_prefix,
                "scopes": k.scopes.split(",") if k.scopes else [],
                "is_active": k.is_active, "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
                "expires_at": k.expires_at.isoformat() if k.expires_at else None,
                "created_at": k.created_at.isoformat(),
            }
            for k in keys
        ]
    }


@router.delete("/orgs/{slug}/api-keys/{key_id}")
def revoke_api_key(slug: str, key_id: int, email: str = Depends(verify_token),
                   db: Session = Depends(get_db)):
    org = verify_org_access(email, slug, "admin", db)
    key = db.query(ApiKey).filter(ApiKey.id == key_id, ApiKey.org_id == org.id).first()
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")
    key.is_active = False
    db.commit()
    return {"message": f"API key '{key.name}' ({key.key_prefix}...) revoked"}


# --- Usage & Billing ---

@router.get("/orgs/{slug}/usage")
def get_usage(slug: str, days: int = 30, email: str = Depends(verify_token),
              db: Session = Depends(get_db)):
    """Get API usage summary for billing."""
    org = verify_org_access(email, slug, "member", db)

    since = datetime.utcnow() - timedelta(days=days)
    records = db.query(UsageRecord).filter(
        UsageRecord.org_id == org.id,
        UsageRecord.created_at >= since,
    ).all()

    total = len(records)
    by_endpoint: dict[str, int] = {}
    avg_latency = 0.0
    for r in records:
        by_endpoint[r.endpoint] = by_endpoint.get(r.endpoint, 0) + 1
        avg_latency += (r.latency_ms or 0)
    if total > 0:
        avg_latency /= total

    return {
        "org": org.slug,
        "plan": org.plan,
        "period_days": days,
        "total_requests": total,
        "avg_latency_ms": round(avg_latency, 2),
        "by_endpoint": by_endpoint,
    }


# --- Webhooks ---

@router.post("/orgs/{slug}/webhooks")
def create_webhook(slug: str, req: CreateWebhookRequest, email: str = Depends(verify_token),
                   db: Session = Depends(get_db)):
    org = verify_org_access(email, slug, "admin", db)

    import secrets
    secret = secrets.token_hex(32)
    webhook = Webhook(org_id=org.id, url=req.url, events=req.events, secret=secret)
    db.add(webhook)
    db.commit()
    db.refresh(webhook)

    return {
        "id": webhook.id,
        "url": webhook.url,
        "events": webhook.events.split(","),
        "secret": secret,
        "message": "Save this secret for verifying webhook signatures (HMAC-SHA256).",
    }


@router.get("/orgs/{slug}/webhooks")
def list_webhooks(slug: str, email: str = Depends(verify_token), db: Session = Depends(get_db)):
    org = verify_org_access(email, slug, "member", db)
    hooks = db.query(Webhook).filter(Webhook.org_id == org.id).all()
    return {
        "webhooks": [
            {"id": h.id, "url": h.url, "events": h.events.split(","),
             "is_active": h.is_active, "created_at": h.created_at.isoformat()}
            for h in hooks
        ]
    }


@router.delete("/orgs/{slug}/webhooks/{webhook_id}")
def delete_webhook(slug: str, webhook_id: int, email: str = Depends(verify_token),
                   db: Session = Depends(get_db)):
    org = verify_org_access(email, slug, "admin", db)
    hook = db.query(Webhook).filter(Webhook.id == webhook_id, Webhook.org_id == org.id).first()
    if not hook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    hook.is_active = False
    db.commit()
    return {"message": "Webhook deactivated"}


# --- Mutation Audit Log ---

@router.get("/audit-log")
def get_mutation_log(resource_type: str | None = None, actor: str | None = None,
                     page: int = 1, limit: int = 50,
                     email: str = Depends(verify_token), db: Session = Depends(get_db)):
    """View the mutation audit trail — who changed what and when."""
    query = db.query(MutationLog)
    if resource_type:
        query = query.filter(MutationLog.resource_type == resource_type)
    if actor:
        query = query.filter(MutationLog.actor.ilike(f"%{actor}%"))
    total = query.count()
    entries = query.order_by(MutationLog.created_at.desc()).offset((page - 1) * limit).limit(limit).all()
    return {
        "total": total,
        "page": page,
        "limit": limit,
        "pages": (total + limit - 1) // limit,
        "entries": [
            {
                "id": e.id,
                "actor": e.actor,
                "action": e.action,
                "resource_type": e.resource_type,
                "resource_id": e.resource_id,
                "details": e.details,
                "created_at": e.created_at.isoformat(),
            }
            for e in entries
        ],
    }
