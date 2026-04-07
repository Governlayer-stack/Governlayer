"""Secretless Credential Injection — JIT token vault with deep-packet injection.

Patent-compliant credential management for autonomous agents. Tokens are:
  - Just-In-Time: issued on demand with TTL <= 60 seconds
  - Transient: automatically expire and are garbage collected
  - Revocable: immediate revocation via token_id
  - Auditable: full issuance/usage/revocation trail

Production deployment would back this with HashiCorp Vault or AWS Secrets Manager.
The in-memory implementation preserves the same interface contract.
"""

import hashlib
import logging
import secrets
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# Maximum TTL for JIT tokens (seconds)
MAX_TTL_SECONDS = 60


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------

@dataclass
class JITToken:
    """A transient just-in-time credential token."""
    token_id: str
    agent_id: str
    scope: str
    issued_at: datetime
    expires_at: datetime
    used: bool = False
    revoked: bool = False
    used_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None


@dataclass
class AuditEntry:
    """Audit trail entry for credential operations."""
    timestamp: datetime
    action: str  # issued, used, revoked, expired_cleanup
    token_id: str
    agent_id: str
    scope: str
    detail: str = ""


# ---------------------------------------------------------------------------
# CredentialVault
# ---------------------------------------------------------------------------

class CredentialVault:
    """In-memory vault for JIT credential tokens.

    Thread-safe. All operations are logged to an internal audit trail.
    Production deployments should replace this with a HashiCorp Vault backend
    while preserving the same public interface.
    """

    def __init__(self) -> None:
        self._tokens: dict[str, JITToken] = {}
        self._token_secrets: dict[str, str] = {}  # token_id -> raw secret
        self._audit_trail: list[AuditEntry] = []
        self._lock = threading.Lock()

    def issue_jit_token(
        self,
        agent_id: str,
        scope: str,
        ttl: int = 60,
    ) -> tuple[str, str]:
        """Generate a transient token with a short TTL.

        Args:
            agent_id: The agent requesting credentials.
            scope: Access scope (e.g. "read:audit", "write:ledger").
            ttl: Time-to-live in seconds. Clamped to MAX_TTL_SECONDS.

        Returns:
            Tuple of (token_id, raw_secret). The raw_secret is only returned
            once — it is not stored in plaintext after this call. The token_id
            is used for all subsequent operations.
        """
        ttl = min(ttl, MAX_TTL_SECONDS)
        if ttl <= 0:
            raise ValueError("TTL must be positive")

        now = datetime.now(timezone.utc)
        token_id = str(uuid.uuid4())
        raw_secret = secrets.token_urlsafe(32)
        hashed_secret = hashlib.sha256(raw_secret.encode()).hexdigest()

        token = JITToken(
            token_id=token_id,
            agent_id=agent_id,
            scope=scope,
            issued_at=now,
            expires_at=now + timedelta(seconds=ttl),
        )

        with self._lock:
            self._tokens[token_id] = token
            self._token_secrets[token_id] = hashed_secret
            self._audit_trail.append(AuditEntry(
                timestamp=now,
                action="issued",
                token_id=token_id,
                agent_id=agent_id,
                scope=scope,
                detail=f"ttl={ttl}s expires_at={token.expires_at.isoformat()}",
            ))

        logger.info(
            "JIT token issued: id=%s agent=%s scope=%s ttl=%ds",
            token_id[:8], agent_id, scope, ttl,
        )
        return token_id, raw_secret

    def inject_credential(self, headers: dict, token_id: str, raw_secret: str) -> dict:
        """Deep-packet injection of credential into request headers.

        Validates the token is active and not expired, then injects the
        credential as an Authorization header. Marks the token as used.

        Args:
            headers: Mutable dict of request headers.
            token_id: The JIT token identifier.
            raw_secret: The raw secret returned from issue_jit_token.

        Returns:
            The modified headers dict with injected credential.

        Raises:
            ValueError: If token is invalid, expired, revoked, or already used.
        """
        now = datetime.now(timezone.utc)

        with self._lock:
            token = self._tokens.get(token_id)
            if token is None:
                raise ValueError(f"Token {token_id} not found")

            if token.revoked:
                raise ValueError(f"Token {token_id} has been revoked")

            if token.used:
                raise ValueError(f"Token {token_id} has already been used")

            if now > token.expires_at:
                raise ValueError(
                    f"Token {token_id} expired at {token.expires_at.isoformat()}"
                )

            # Verify the secret
            expected_hash = self._token_secrets.get(token_id)
            provided_hash = hashlib.sha256(raw_secret.encode()).hexdigest()
            if expected_hash != provided_hash:
                raise ValueError(f"Invalid secret for token {token_id}")

            # Mark as used and inject
            token.used = True
            token.used_at = now
            self._audit_trail.append(AuditEntry(
                timestamp=now,
                action="used",
                token_id=token_id,
                agent_id=token.agent_id,
                scope=token.scope,
            ))

        # Inject into headers (deep-packet injection)
        headers["Authorization"] = f"Bearer jit:{token_id}:{raw_secret}"
        headers["X-GovernLayer-Agent"] = token.agent_id
        headers["X-GovernLayer-Scope"] = token.scope
        headers["X-GovernLayer-Token-Id"] = token_id

        logger.info("Credential injected: token=%s agent=%s", token_id[:8], token.agent_id)
        return headers

    def revoke_token(self, token_id: str) -> bool:
        """Immediately revoke a token.

        Args:
            token_id: The token to revoke.

        Returns:
            True if revoked, False if token not found.
        """
        now = datetime.now(timezone.utc)

        with self._lock:
            token = self._tokens.get(token_id)
            if token is None:
                return False

            token.revoked = True
            token.revoked_at = now
            # Remove the secret — token can never be used
            self._token_secrets.pop(token_id, None)

            self._audit_trail.append(AuditEntry(
                timestamp=now,
                action="revoked",
                token_id=token_id,
                agent_id=token.agent_id,
                scope=token.scope,
            ))

        logger.info("Token revoked: id=%s agent=%s", token_id[:8], token.agent_id)
        return True

    def cleanup_expired(self) -> int:
        """Garbage collect expired tokens.

        Returns:
            Number of tokens cleaned up.
        """
        now = datetime.now(timezone.utc)
        cleaned = 0

        with self._lock:
            expired_ids = [
                tid for tid, t in self._tokens.items()
                if now > t.expires_at and t.token_id not in (
                    # Keep resolved tokens for audit trail but clean secrets
                )
            ]
            for tid in expired_ids:
                token = self._tokens[tid]
                if not token.revoked and not token.used:
                    self._audit_trail.append(AuditEntry(
                        timestamp=now,
                        action="expired_cleanup",
                        token_id=tid,
                        agent_id=token.agent_id,
                        scope=token.scope,
                    ))
                self._token_secrets.pop(tid, None)
                del self._tokens[tid]
                cleaned += 1

        if cleaned:
            logger.info("Cleaned up %d expired tokens", cleaned)
        return cleaned

    def list_active_tokens(self) -> list[dict]:
        """List all currently active (non-expired, non-revoked, non-used) tokens."""
        now = datetime.now(timezone.utc)
        result = []

        with self._lock:
            for token in self._tokens.values():
                if token.revoked or token.used or now > token.expires_at:
                    continue
                result.append({
                    "token_id": token.token_id,
                    "agent_id": token.agent_id,
                    "scope": token.scope,
                    "issued_at": token.issued_at.isoformat(),
                    "expires_at": token.expires_at.isoformat(),
                    "remaining_seconds": (token.expires_at - now).total_seconds(),
                })

        return result

    def get_audit_trail(self, limit: int = 100) -> list[dict]:
        """Return the most recent audit trail entries."""
        with self._lock:
            entries = self._audit_trail[-limit:]

        return [
            {
                "timestamp": e.timestamp.isoformat(),
                "action": e.action,
                "token_id": e.token_id,
                "agent_id": e.agent_id,
                "scope": e.scope,
                "detail": e.detail,
            }
            for e in reversed(entries)
        ]


# ---------------------------------------------------------------------------
# Singleton vault instance
# ---------------------------------------------------------------------------

_vault: Optional[CredentialVault] = None
_vault_lock = threading.Lock()


def get_vault() -> CredentialVault:
    """Get or create the singleton CredentialVault."""
    global _vault
    if _vault is None:
        with _vault_lock:
            if _vault is None:
                _vault = CredentialVault()
    return _vault
