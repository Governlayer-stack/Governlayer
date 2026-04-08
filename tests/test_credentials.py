"""Tests for Secretless Credential Injection — JIT token vault.

Validates the patent-compliant credential management system:
    - JIT token issuance with TTL <= 60s
    - Token injection into request headers
    - Token expiration
    - Token revocation
    - Used token rejection
    - Cleanup of expired tokens
"""

import time
from datetime import datetime, timedelta, timezone

import pytest

from src.security.credentials import (
    CredentialVault,
    MAX_TTL_SECONDS,
    get_vault,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def vault():
    """Create a fresh CredentialVault for each test."""
    return CredentialVault()


# ═══════════════════════════════════════════════════════════════════════════
# JIT Token Issuance
# ═══════════════════════════════════════════════════════════════════════════

class TestJITTokenIssuance:
    """Test just-in-time token generation."""

    def test_issue_returns_token_id_and_secret(self, vault):
        token_id, secret = vault.issue_jit_token("agent-1", "read:audit")
        assert token_id is not None
        assert secret is not None
        assert len(token_id) > 0
        assert len(secret) > 0

    def test_issue_token_default_ttl(self, vault):
        token_id, _ = vault.issue_jit_token("agent-1", "read:audit")
        active = vault.list_active_tokens()
        assert len(active) == 1
        token_info = active[0]
        assert token_info["token_id"] == token_id
        assert token_info["remaining_seconds"] <= MAX_TTL_SECONDS
        assert token_info["remaining_seconds"] > 0

    def test_issue_token_custom_ttl(self, vault):
        token_id, _ = vault.issue_jit_token("agent-1", "read:audit", ttl=30)
        active = vault.list_active_tokens()
        assert active[0]["remaining_seconds"] <= 30

    def test_ttl_clamped_to_max(self, vault):
        """Requesting TTL > MAX_TTL_SECONDS should be clamped."""
        token_id, _ = vault.issue_jit_token("agent-1", "read:audit", ttl=300)
        active = vault.list_active_tokens()
        assert active[0]["remaining_seconds"] <= MAX_TTL_SECONDS

    def test_ttl_zero_raises(self, vault):
        with pytest.raises(ValueError, match="positive"):
            vault.issue_jit_token("agent-1", "read:audit", ttl=0)

    def test_ttl_negative_raises(self, vault):
        with pytest.raises(ValueError, match="positive"):
            vault.issue_jit_token("agent-1", "read:audit", ttl=-10)

    def test_unique_token_ids(self, vault):
        t1, _ = vault.issue_jit_token("agent-1", "scope-a")
        t2, _ = vault.issue_jit_token("agent-1", "scope-a")
        assert t1 != t2

    def test_unique_secrets(self, vault):
        _, s1 = vault.issue_jit_token("agent-1", "scope-a")
        _, s2 = vault.issue_jit_token("agent-1", "scope-a")
        assert s1 != s2

    def test_audit_trail_records_issuance(self, vault):
        vault.issue_jit_token("agent-1", "read:audit")
        trail = vault.get_audit_trail()
        assert len(trail) == 1
        assert trail[0]["action"] == "issued"
        assert trail[0]["agent_id"] == "agent-1"
        assert trail[0]["scope"] == "read:audit"


# ═══════════════════════════════════════════════════════════════════════════
# Token Injection into Headers
# ═══════════════════════════════════════════════════════════════════════════

class TestTokenInjection:
    """Test deep-packet credential injection into request headers."""

    def test_inject_credential_adds_headers(self, vault):
        token_id, secret = vault.issue_jit_token("agent-1", "read:audit")
        headers = {"Content-Type": "application/json"}
        result = vault.inject_credential(headers, token_id, secret)

        assert "Authorization" in result
        assert result["Authorization"].startswith("Bearer jit:")
        assert result["X-GovernLayer-Agent"] == "agent-1"
        assert result["X-GovernLayer-Scope"] == "read:audit"
        assert result["X-GovernLayer-Token-Id"] == token_id

    def test_inject_preserves_existing_headers(self, vault):
        token_id, secret = vault.issue_jit_token("agent-1", "read:audit")
        headers = {"Content-Type": "application/json", "Accept": "text/html"}
        result = vault.inject_credential(headers, token_id, secret)
        assert result["Content-Type"] == "application/json"
        assert result["Accept"] == "text/html"

    def test_inject_marks_token_as_used(self, vault):
        token_id, secret = vault.issue_jit_token("agent-1", "read:audit")
        vault.inject_credential({}, token_id, secret)
        # Token should no longer be in active list
        active = vault.list_active_tokens()
        assert len(active) == 0

    def test_inject_audit_trail(self, vault):
        token_id, secret = vault.issue_jit_token("agent-1", "read:audit")
        vault.inject_credential({}, token_id, secret)
        trail = vault.get_audit_trail()
        actions = [e["action"] for e in trail]
        assert "issued" in actions
        assert "used" in actions

    def test_inject_invalid_secret_raises(self, vault):
        token_id, _ = vault.issue_jit_token("agent-1", "read:audit")
        with pytest.raises(ValueError, match="Invalid secret"):
            vault.inject_credential({}, token_id, "wrong-secret")

    def test_inject_nonexistent_token_raises(self, vault):
        with pytest.raises(ValueError, match="not found"):
            vault.inject_credential({}, "fake-id", "fake-secret")


# ═══════════════════════════════════════════════════════════════════════════
# Token Expiration
# ═══════════════════════════════════════════════════════════════════════════

class TestTokenExpiration:
    """Test that tokens expire correctly after their TTL."""

    def test_expired_token_cannot_be_injected(self, vault):
        token_id, secret = vault.issue_jit_token("agent-1", "read:audit", ttl=1)
        # Manually expire the token by backdating
        with vault._lock:
            vault._tokens[token_id].expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        with pytest.raises(ValueError, match="expired"):
            vault.inject_credential({}, token_id, secret)

    def test_expired_token_not_in_active_list(self, vault):
        token_id, _ = vault.issue_jit_token("agent-1", "read:audit", ttl=1)
        with vault._lock:
            vault._tokens[token_id].expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        active = vault.list_active_tokens()
        assert len(active) == 0

    def test_max_ttl_enforced(self):
        assert MAX_TTL_SECONDS == 60


# ═══════════════════════════════════════════════════════════════════════════
# Token Revocation
# ═══════════════════════════════════════════════════════════════════════════

class TestTokenRevocation:
    """Test immediate token revocation."""

    def test_revoke_active_token(self, vault):
        token_id, _ = vault.issue_jit_token("agent-1", "read:audit")
        result = vault.revoke_token(token_id)
        assert result is True

    def test_revoked_token_cannot_be_injected(self, vault):
        token_id, secret = vault.issue_jit_token("agent-1", "read:audit")
        vault.revoke_token(token_id)
        with pytest.raises(ValueError, match="revoked"):
            vault.inject_credential({}, token_id, secret)

    def test_revoke_nonexistent_token(self, vault):
        result = vault.revoke_token("nonexistent-id")
        assert result is False

    def test_revoked_token_not_in_active_list(self, vault):
        token_id, _ = vault.issue_jit_token("agent-1", "read:audit")
        vault.revoke_token(token_id)
        active = vault.list_active_tokens()
        assert len(active) == 0

    def test_revocation_audit_trail(self, vault):
        token_id, _ = vault.issue_jit_token("agent-1", "read:audit")
        vault.revoke_token(token_id)
        trail = vault.get_audit_trail()
        actions = [e["action"] for e in trail]
        assert "revoked" in actions


# ═══════════════════════════════════════════════════════════════════════════
# Used Token Rejection
# ═══════════════════════════════════════════════════════════════════════════

class TestUsedTokenRejection:
    """Test that tokens can only be used once."""

    def test_token_single_use_only(self, vault):
        token_id, secret = vault.issue_jit_token("agent-1", "read:audit")
        # First use succeeds
        vault.inject_credential({}, token_id, secret)
        # Second use fails
        with pytest.raises(ValueError, match="already been used"):
            vault.inject_credential({}, token_id, secret)

    def test_used_token_not_active(self, vault):
        token_id, secret = vault.issue_jit_token("agent-1", "read:audit")
        vault.inject_credential({}, token_id, secret)
        active = vault.list_active_tokens()
        assert all(t["token_id"] != token_id for t in active)


# ═══════════════════════════════════════════════════════════════════════════
# Cleanup of Expired Tokens
# ═══════════════════════════════════════════════════════════════════════════

class TestExpiredTokenCleanup:
    """Test garbage collection of expired tokens."""

    def test_cleanup_removes_expired(self, vault):
        token_id, _ = vault.issue_jit_token("agent-1", "read:audit", ttl=1)
        # Backdate the token to be expired
        with vault._lock:
            vault._tokens[token_id].expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
        cleaned = vault.cleanup_expired()
        assert cleaned == 1

    def test_cleanup_does_not_remove_active(self, vault):
        vault.issue_jit_token("agent-1", "read:audit", ttl=60)
        cleaned = vault.cleanup_expired()
        assert cleaned == 0
        active = vault.list_active_tokens()
        assert len(active) == 1

    def test_cleanup_records_audit_trail(self, vault):
        token_id, _ = vault.issue_jit_token("agent-1", "read:audit", ttl=1)
        with vault._lock:
            vault._tokens[token_id].expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
        vault.cleanup_expired()
        trail = vault.get_audit_trail()
        actions = [e["action"] for e in trail]
        assert "expired_cleanup" in actions

    def test_cleanup_multiple_expired(self, vault):
        for i in range(5):
            tid, _ = vault.issue_jit_token(f"agent-{i}", "scope")
            with vault._lock:
                vault._tokens[tid].expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
        cleaned = vault.cleanup_expired()
        assert cleaned == 5

    def test_cleanup_mixed_active_and_expired(self, vault):
        # Create 3 expired
        expired_ids = []
        for i in range(3):
            tid, _ = vault.issue_jit_token(f"expired-{i}", "scope")
            with vault._lock:
                vault._tokens[tid].expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
            expired_ids.append(tid)

        # Create 2 active
        for i in range(2):
            vault.issue_jit_token(f"active-{i}", "scope")

        cleaned = vault.cleanup_expired()
        assert cleaned == 3
        active = vault.list_active_tokens()
        assert len(active) == 2


# ═══════════════════════════════════════════════════════════════════════════
# Singleton Vault
# ═══════════════════════════════════════════════════════════════════════════

class TestSingletonVault:
    """Test the global singleton vault accessor."""

    def test_get_vault_returns_credential_vault(self):
        vault = get_vault()
        assert isinstance(vault, CredentialVault)

    def test_get_vault_is_singleton(self):
        v1 = get_vault()
        v2 = get_vault()
        assert v1 is v2


# ═══════════════════════════════════════════════════════════════════════════
# Audit Trail
# ═══════════════════════════════════════════════════════════════════════════

class TestAuditTrail:
    """Test the credential audit trail."""

    def test_trail_ordered_most_recent_first(self, vault):
        vault.issue_jit_token("agent-1", "scope-a")
        vault.issue_jit_token("agent-2", "scope-b")
        trail = vault.get_audit_trail()
        assert trail[0]["agent_id"] == "agent-2"
        assert trail[1]["agent_id"] == "agent-1"

    def test_trail_limit(self, vault):
        for i in range(10):
            vault.issue_jit_token(f"agent-{i}", "scope")
        trail = vault.get_audit_trail(limit=3)
        assert len(trail) == 3

    def test_trail_full_lifecycle(self, vault):
        token_id, secret = vault.issue_jit_token("agent-1", "read:audit")
        vault.inject_credential({}, token_id, secret)
        trail = vault.get_audit_trail()
        actions = [e["action"] for e in trail]
        assert "issued" in actions
        assert "used" in actions

    def test_trail_has_timestamps(self, vault):
        vault.issue_jit_token("agent-1", "scope")
        trail = vault.get_audit_trail()
        assert "timestamp" in trail[0]
        # Should be ISO format
        datetime.fromisoformat(trail[0]["timestamp"])
