"""Secretless Credential Injection — API endpoints.

Provides REST endpoints for JIT token issuance, revocation, and audit trail
for the patent-compliant secretless credential injection system.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from src.security.auth import verify_token
from src.security.credentials import get_vault

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/credentials", tags=["credentials"])


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class IssueTokenRequest(BaseModel):
    """Request to issue a new JIT credential token."""
    agent_id: str = Field(..., min_length=1, max_length=255, description="Agent identifier")
    scope: str = Field(..., min_length=1, max_length=255, description="Access scope, e.g. 'read:audit'")
    ttl: int = Field(default=60, ge=1, le=60, description="Time-to-live in seconds (max 60)")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/issue")
def issue_token(
    request: IssueTokenRequest,
    email: str = Depends(verify_token),
):
    """Issue a just-in-time credential token for an agent.

    The raw_secret is returned exactly once. Store it securely — it cannot
    be retrieved again. The token expires after the specified TTL (max 60s).
    """
    vault = get_vault()
    try:
        token_id, raw_secret = vault.issue_jit_token(
            agent_id=request.agent_id,
            scope=request.scope,
            ttl=request.ttl,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {
        "status": "issued",
        "token_id": token_id,
        "raw_secret": raw_secret,
        "agent_id": request.agent_id,
        "scope": request.scope,
        "ttl_seconds": min(request.ttl, 60),
        "issued_by": email,
        "warning": "The raw_secret is returned only once. Store it securely.",
    }


@router.post("/revoke/{token_id}")
def revoke_token(
    token_id: str,
    email: str = Depends(verify_token),
):
    """Immediately revoke a JIT credential token.

    The token can no longer be used for credential injection after revocation.
    """
    vault = get_vault()
    revoked = vault.revoke_token(token_id)
    if not revoked:
        raise HTTPException(status_code=404, detail=f"Token {token_id} not found")

    return {
        "status": "revoked",
        "token_id": token_id,
        "revoked_by": email,
    }


@router.get("/active")
def list_active(email: str = Depends(verify_token)):
    """List all currently active (non-expired, non-revoked, non-used) JIT tokens."""
    vault = get_vault()

    # Run cleanup first to remove stale tokens
    cleaned = vault.cleanup_expired()

    tokens = vault.list_active_tokens()
    return {
        "count": len(tokens),
        "tokens": tokens,
        "cleaned_expired": cleaned,
    }


@router.get("/audit")
def audit_trail(
    limit: int = 100,
    email: str = Depends(verify_token),
):
    """Token usage audit trail — most recent credential operations.

    Returns issuance, usage, revocation, and expiry events in reverse
    chronological order.
    """
    vault = get_vault()
    entries = vault.get_audit_trail(limit=min(limit, 500))
    return {
        "count": len(entries),
        "entries": entries,
    }
