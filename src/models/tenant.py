"""Multi-tenant models — Organizations, API keys, usage metering, webhooks."""

import hashlib
import secrets
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import relationship

from src.models.database import Base


class Organization(Base):
    __tablename__ = "organizations"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, index=True, nullable=False)
    plan = Column(String(50), default="free", nullable=False)  # free, starter, pro, enterprise
    stripe_customer_id = Column(String(255), nullable=True)
    stripe_subscription_id = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    api_keys = relationship("ApiKey", back_populates="organization")
    webhooks = relationship("Webhook", back_populates="organization")


class ApiKey(Base):
    __tablename__ = "api_keys"
    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    name = Column(String(255), nullable=False)  # e.g. "production", "staging"
    key_prefix = Column(String(12), nullable=False)  # first chars for identification (gl_xxxxxxx)
    key_hash = Column(String(64), unique=True, nullable=False)  # SHA-256 of full key
    scopes = Column(Text, default="govern,audit,risk,scan")  # comma-separated
    rate_limit = Column(Integer, default=100)  # requests per minute
    is_active = Column(Boolean, default=True, nullable=False)
    last_used_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    organization = relationship("Organization", back_populates="api_keys")

    __table_args__ = (Index("ix_api_keys_key_hash", "key_hash"),)


class UsageRecord(Base):
    __tablename__ = "usage_records"
    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    api_key_id = Column(Integer, ForeignKey("api_keys.id"), nullable=True)
    endpoint = Column(String(255), nullable=False)
    method = Column(String(10), nullable=False)
    status_code = Column(Integer, nullable=False)
    latency_ms = Column(Float, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (Index("ix_usage_org_date", "org_id", "created_at"),)


class OrgMembership(Base):
    __tablename__ = "org_memberships"
    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String(255), nullable=False, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    role = Column(String(20), nullable=False, default="member")  # owner, admin, member, viewer
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    organization = relationship("Organization")

    __table_args__ = (
        Index("ix_org_membership_user_org", "user_email", "org_id", unique=True),
    )


# Role hierarchy for access checks (higher number = more privilege)
_ROLE_RANK = {"viewer": 0, "member": 1, "admin": 2, "owner": 3}


def verify_org_access(user_email: str, org_slug: str, required_role: str, db) -> Organization:
    """Check that user_email is a member of the org with at least required_role.

    Returns the Organization on success, raises HTTPException on failure.
    """
    from fastapi import HTTPException

    org = db.query(Organization).filter(Organization.slug == org_slug).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    membership = (
        db.query(OrgMembership)
        .filter(OrgMembership.user_email == user_email, OrgMembership.org_id == org.id)
        .first()
    )
    if not membership:
        raise HTTPException(status_code=403, detail="You are not a member of this organization")

    if _ROLE_RANK.get(membership.role, -1) < _ROLE_RANK.get(required_role, 99):
        raise HTTPException(status_code=403, detail=f"Requires at least '{required_role}' role in this organization")

    return org


class Webhook(Base):
    __tablename__ = "webhooks"
    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    url = Column(String(2048), nullable=False)
    events = Column(Text, default="governance.decision,audit.complete")  # comma-separated
    secret = Column(String(64), nullable=False)  # for HMAC signature verification
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    organization = relationship("Organization", back_populates="webhooks")


# --- Key generation utilities ---

def generate_api_key() -> tuple[str, str, str]:
    """Generate an API key. Returns (full_key, prefix, hash)."""
    raw = secrets.token_urlsafe(32)
    full_key = f"gl_{raw}"
    prefix = full_key[:10]
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()
    return full_key, prefix, key_hash


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()
