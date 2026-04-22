"""Policy Management API — CRUD + evaluation."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.models.database import get_db
from src.models.policy import GovernancePolicy
from src.governance.policy_engine import evaluate_policy, DEFAULT_POLICY
from src.security.api_key_auth import AuthContext, verify_api_key_or_jwt

router = APIRouter(prefix="/v1/policies", tags=["Policies"])


class PolicyCreate(BaseModel):
    name: str
    description: Optional[str] = None
    version: str = "1.0"
    rules: List[Dict[str, Any]] = Field(default_factory=list)
    created_by: Optional[str] = None


class PolicyEvaluate(BaseModel):
    context: Dict[str, Any]
    policy_id: Optional[int] = None


@router.post("")
def create_policy(data: PolicyCreate, auth: AuthContext = Depends(verify_api_key_or_jwt),
                  db: Session = Depends(get_db)):
    """Create a new governance policy."""
    policy = GovernancePolicy(
        name=data.name,
        description=data.description,
        version=data.version,
        rules=data.rules,
        created_by=data.created_by,
        org_id=auth.org_id,
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return {
        "id": policy.id,
        "name": policy.name,
        "version": policy.version,
        "rules_count": len(policy.rules) if policy.rules else 0,
        "created_at": policy.created_at.isoformat() if policy.created_at else None,
    }


@router.get("")
def list_policies(active_only: bool = True, auth: AuthContext = Depends(verify_api_key_or_jwt),
                  db: Session = Depends(get_db)):
    """List all governance policies."""
    query = db.query(GovernancePolicy)
    if auth.org_id:
        query = query.filter(GovernancePolicy.org_id == auth.org_id)
    if active_only:
        query = query.filter(GovernancePolicy.is_active == True)
    policies = query.order_by(GovernancePolicy.created_at.desc()).all()
    return {
        "total": len(policies),
        "policies": [
            {
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "version": p.version,
                "rules_count": len(p.rules) if p.rules else 0,
                "is_active": p.is_active,
                "created_at": p.created_at.isoformat() if p.created_at else None,
            }
            for p in policies
        ],
    }


@router.get("/{policy_id}")
def get_policy(policy_id: int, auth: AuthContext = Depends(verify_api_key_or_jwt),
               db: Session = Depends(get_db)):
    """Get a specific policy with all rules."""
    policy = db.query(GovernancePolicy).filter(GovernancePolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    if auth.org_id and policy.org_id != auth.org_id:
        raise HTTPException(status_code=404, detail="Policy not found")
    return {
        "id": policy.id,
        "name": policy.name,
        "description": policy.description,
        "version": policy.version,
        "rules": policy.rules,
        "is_active": policy.is_active,
        "created_by": policy.created_by,
        "created_at": policy.created_at.isoformat() if policy.created_at else None,
        "updated_at": policy.updated_at.isoformat() if policy.updated_at else None,
    }


@router.post("/evaluate")
def evaluate(data: PolicyEvaluate, auth: AuthContext = Depends(verify_api_key_or_jwt),
             db: Session = Depends(get_db)):
    """Evaluate context against a policy (or default policy)."""
    if data.policy_id:
        policy_record = db.query(GovernancePolicy).filter(GovernancePolicy.id == data.policy_id).first()
        if not policy_record:
            raise HTTPException(status_code=404, detail="Policy not found")
        if auth.org_id and policy_record.org_id != auth.org_id:
            raise HTTPException(status_code=404, detail="Policy not found")
        policy = {
            "name": policy_record.name,
            "version": policy_record.version,
            "rules": policy_record.rules or [],
        }
    else:
        policy = DEFAULT_POLICY

    return evaluate_policy(context=data.context, policy=policy)


@router.delete("/{policy_id}")
def deactivate_policy(policy_id: int, auth: AuthContext = Depends(verify_api_key_or_jwt),
                      db: Session = Depends(get_db)):
    """Deactivate a policy (soft delete)."""
    policy = db.query(GovernancePolicy).filter(GovernancePolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    if auth.org_id and policy.org_id != auth.org_id:
        raise HTTPException(status_code=404, detail="Policy not found")
    policy.is_active = False
    policy.updated_at = datetime.utcnow()
    db.commit()
    return {"id": policy.id, "name": policy.name, "is_active": False}
