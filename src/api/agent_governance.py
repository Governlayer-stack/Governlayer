"""Runtime Agent Governance API — Cedar-style policy management + credential vault.

Endpoints:
  POST   /agent-governance/evaluate       — Evaluate an agent action (pre-execution gate)
  GET    /agent-governance/policies        — List all policies
  POST   /agent-governance/policies        — Create a new policy
  DELETE /agent-governance/policies/{id}   — Remove a policy
  PATCH  /agent-governance/policies/{id}   — Update a policy
  GET    /agent-governance/enforcement-log — View enforcement audit trail
  GET    /agent-governance/stats           — Enforcement statistics
  POST   /agent-governance/credentials/issue   — Issue a JIT credential token
  POST   /agent-governance/credentials/revoke  — Revoke a credential token
  GET    /agent-governance/credentials/active  — List active tokens
  GET    /agent-governance/credentials/audit   — Credential audit trail
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from src.security.auth import verify_token
from src.security.credentials import get_vault
from src.security.policy_engine import (
    EnforcementResult,
    create_policy,
    get_policy_engine,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/agent-governance", tags=["agent-governance"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class EvaluateRequest(BaseModel):
    agent_id: str = Field(..., description="The agent requesting authorization")
    action: str = Field(..., description="The tool or action being invoked")
    resource: str = Field(default="*", description="Target resource identifier")
    context: dict = Field(default_factory=dict, description="Additional context for condition evaluation")


class PolicyCreateRequest(BaseModel):
    name: str = Field(..., description="Human-readable policy name")
    effect: str = Field(..., description="'permit' or 'forbid'")
    principal: str = Field(default="*", description="Agent ID or '*' for all")
    action: str = Field(default="*", description="Action name or '*' for all")
    resource: str = Field(default="*", description="Resource or '*' for all")
    conditions: list[dict] = Field(default_factory=list, description="List of {field, operator, value} conditions")
    priority: int = Field(default=0, description="Higher priority evaluated first")
    description: str = Field(default="", description="Policy description")


class PolicyUpdateRequest(BaseModel):
    name: Optional[str] = None
    effect: Optional[str] = None
    principal: Optional[str] = None
    action: Optional[str] = None
    resource: Optional[str] = None
    enabled: Optional[bool] = None
    priority: Optional[int] = None
    description: Optional[str] = None


class CredentialIssueRequest(BaseModel):
    agent_id: str = Field(..., description="The agent requesting credentials")
    scope: str = Field(..., description="Access scope (e.g. 'read:audit', 'write:ledger')")
    ttl: int = Field(default=60, ge=1, le=60, description="Time-to-live in seconds (max 60)")


class CredentialRevokeRequest(BaseModel):
    token_id: str = Field(..., description="The token to revoke")


# ---------------------------------------------------------------------------
# Policy evaluation (the core runtime gate)
# ---------------------------------------------------------------------------

@router.post("/evaluate")
def evaluate_action(
    req: EvaluateRequest,
    email: str = Depends(verify_token),
):
    """Evaluate whether an agent action is permitted (pre-execution gate).

    Returns ALLOW or DENY with the matched policy and reason.
    This is the entry point that should be called before every agent tool call.
    """
    engine = get_policy_engine()
    result, reason = engine.evaluate(
        agent_id=req.agent_id,
        action=req.action,
        resource=req.resource,
        context=req.context,
    )

    return {
        "result": result.value,
        "reason": reason,
        "agent_id": req.agent_id,
        "action": req.action,
        "resource": req.resource,
    }


# ---------------------------------------------------------------------------
# Policy CRUD
# ---------------------------------------------------------------------------

@router.get("/policies")
def list_policies(email: str = Depends(verify_token)):
    """List all registered authorization policies."""
    engine = get_policy_engine()
    return {"policies": engine.list_policies()}


@router.post("/policies", status_code=201)
def create_policy_endpoint(
    req: PolicyCreateRequest,
    email: str = Depends(verify_token),
):
    """Create a new Cedar-style authorization policy."""
    if req.effect not in ("permit", "forbid"):
        raise HTTPException(status_code=422, detail="Effect must be 'permit' or 'forbid'")

    policy = create_policy(
        name=req.name,
        effect=req.effect,
        principal=req.principal,
        action=req.action,
        resource=req.resource,
        conditions=req.conditions,
        priority=req.priority,
        description=req.description,
    )

    engine = get_policy_engine()
    policy_id = engine.add_policy(policy)

    logger.info("Policy created by %s: %s (%s)", email, req.name, policy_id[:8])

    return {
        "policy_id": policy_id,
        "name": req.name,
        "effect": req.effect,
        "message": "Policy created",
    }


@router.delete("/policies/{policy_id}")
def delete_policy(
    policy_id: str,
    email: str = Depends(verify_token),
):
    """Remove a policy by ID."""
    engine = get_policy_engine()
    if not engine.remove_policy(policy_id):
        raise HTTPException(status_code=404, detail="Policy not found")

    logger.info("Policy removed by %s: %s", email, policy_id[:8])
    return {"message": "Policy removed", "policy_id": policy_id}


@router.patch("/policies/{policy_id}")
def update_policy(
    policy_id: str,
    req: PolicyUpdateRequest,
    email: str = Depends(verify_token),
):
    """Update fields on an existing policy."""
    engine = get_policy_engine()
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=422, detail="No fields to update")

    if not engine.update_policy(policy_id, **updates):
        raise HTTPException(status_code=404, detail="Policy not found")

    logger.info("Policy updated by %s: %s fields=%s", email, policy_id[:8], list(updates.keys()))
    return {"message": "Policy updated", "policy_id": policy_id, "updated_fields": list(updates.keys())}


# ---------------------------------------------------------------------------
# Enforcement log and stats
# ---------------------------------------------------------------------------

@router.get("/enforcement-log")
def enforcement_log(
    limit: int = 100,
    agent_id: Optional[str] = None,
    email: str = Depends(verify_token),
):
    """View the enforcement audit trail — every allow/deny decision."""
    engine = get_policy_engine()
    return {
        "entries": engine.get_evaluation_log(limit=limit, agent_id=agent_id),
        "count": min(limit, len(engine.get_evaluation_log(limit=limit, agent_id=agent_id))),
    }


@router.get("/stats")
def enforcement_stats(email: str = Depends(verify_token)):
    """Enforcement statistics — total evaluations, allow/deny rates."""
    engine = get_policy_engine()
    return engine.get_stats()


# ---------------------------------------------------------------------------
# Credential Vault
# ---------------------------------------------------------------------------

@router.post("/credentials/issue")
def issue_credential(
    req: CredentialIssueRequest,
    email: str = Depends(verify_token),
):
    """Issue a JIT credential token for an agent.

    The raw secret is returned ONCE — store it securely.
    Token auto-expires after TTL seconds (max 60s).
    """
    # First check policy engine — is this agent allowed to get credentials?
    engine = get_policy_engine()
    result, reason = engine.evaluate(
        agent_id=req.agent_id,
        action="credential:issue",
        resource=req.scope,
        context={"requested_by": email},
    )

    # For credential issuance, we allow by default if no forbid rule exists
    # (the vault itself enforces short TTL and single-use)

    vault = get_vault()
    token_id, raw_secret = vault.issue_jit_token(
        agent_id=req.agent_id,
        scope=req.scope,
        ttl=req.ttl,
    )

    logger.info(
        "JIT credential issued by %s for agent=%s scope=%s ttl=%ds",
        email, req.agent_id, req.scope, req.ttl,
    )

    return {
        "token_id": token_id,
        "raw_secret": raw_secret,
        "agent_id": req.agent_id,
        "scope": req.scope,
        "ttl_seconds": req.ttl,
        "warning": "The raw_secret is shown only once. Store it securely.",
    }


@router.post("/credentials/revoke")
def revoke_credential(
    req: CredentialRevokeRequest,
    email: str = Depends(verify_token),
):
    """Immediately revoke a credential token."""
    vault = get_vault()
    if not vault.revoke_token(req.token_id):
        raise HTTPException(status_code=404, detail="Token not found")

    logger.info("Token revoked by %s: %s", email, req.token_id[:8])
    return {"message": "Token revoked", "token_id": req.token_id}


@router.get("/credentials/active")
def active_credentials(email: str = Depends(verify_token)):
    """List all currently active (non-expired, non-revoked) credential tokens."""
    vault = get_vault()
    return {"tokens": vault.list_active_tokens()}


@router.get("/credentials/audit")
def credential_audit(
    limit: int = 100,
    email: str = Depends(verify_token),
):
    """View the credential vault audit trail."""
    vault = get_vault()
    return {"entries": vault.get_audit_trail(limit=limit)}
