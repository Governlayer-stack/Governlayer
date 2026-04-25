"""API Key authentication for enterprise integrations.

Enterprise users authenticate with: Authorization: Bearer gl_xxxxx
Existing JWT auth continues to work alongside API keys.
"""

from datetime import datetime

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from src.config import get_settings
from src.models.database import get_db
from src.models.tenant import ApiKey, hash_api_key

settings = get_settings()
security = HTTPBearer()

# Default scopes for JWT-authenticated users (no "admin" scope)
JWT_DEFAULT_SCOPES = ["govern", "audit", "risk", "scan", "read"]


class AuthContext:
    """Unified auth result — works for both JWT users and API key tenants."""
    def __init__(self, identity: str, org_id: int | None = None, scopes: list[str] | None = None,
                 auth_type: str = "jwt", api_key_id: int | None = None):
        self.identity = identity
        self.org_id = org_id
        self.scopes = scopes or []
        self.auth_type = auth_type
        self.api_key_id = api_key_id

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


def verify_api_key_or_jwt(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> AuthContext:
    """Authenticate via API key (gl_xxx) or JWT token. Returns unified AuthContext."""
    token = credentials.credentials

    # API key path
    if token.startswith("gl_"):
        key_hash = hash_api_key(token)
        api_key = db.query(ApiKey).filter(ApiKey.key_hash == key_hash, ApiKey.is_active.is_(True)).first()
        if not api_key:
            raise HTTPException(status_code=401, detail="Invalid API key")
        if api_key.expires_at and api_key.expires_at < datetime.utcnow():
            raise HTTPException(status_code=401, detail="API key expired")
        # Update last used
        api_key.last_used_at = datetime.utcnow()
        db.commit()
        scopes = [s.strip() for s in (api_key.scopes or "").split(",") if s.strip()]
        return AuthContext(
            identity=f"org:{api_key.org_id}:{api_key.name}",
            org_id=api_key.org_id,
            scopes=scopes,
            auth_type="api_key",
            api_key_id=api_key.id,
        )

    # JWT path
    from src.security.auth import verify_token_raw
    email = verify_token_raw(token)

    # Enforce email verification for JWT users
    from src.models.database import User
    user = db.query(User).filter(User.email == email).first()
    if user and not user.email_verified:
        raise HTTPException(
            status_code=403,
            detail="Email not verified. Check your inbox or POST /auth/resend-verification",
        )

    # Resolve org from membership
    from src.models.tenant import OrgMembership
    membership = db.query(OrgMembership).filter(OrgMembership.user_email == email).first()
    org_id = membership.org_id if membership else None
    return AuthContext(identity=email, org_id=org_id, auth_type="jwt", scopes=list(JWT_DEFAULT_SCOPES))


def require_scope(scope: str):
    """Dependency that checks if the auth context has the required scope."""
    def checker(auth: AuthContext = Depends(verify_api_key_or_jwt)):
        if not auth.has_scope(scope):
            raise HTTPException(status_code=403, detail=f"Missing required scope: {scope}")
        return auth
    return checker


PLAN_HIERARCHY = {"free": 0, "starter": 1, "pro": 2, "enterprise": 3}


def require_plan(minimum_plan: str):
    """Dependency that gates features behind a minimum plan tier."""
    min_level = PLAN_HIERARCHY.get(minimum_plan, 0)

    def checker(auth: AuthContext = Depends(verify_api_key_or_jwt), db: Session = Depends(get_db)):
        if auth.org_id is None:
            raise HTTPException(
                status_code=403,
                detail="No organization found. Create one first: POST /v1/enterprise/orgs",
            )
        from src.models.tenant import Organization
        org = db.query(Organization).filter(Organization.id == auth.org_id).first()
        if not org:
            raise HTTPException(status_code=403, detail="Organization not found")
        org_level = PLAN_HIERARCHY.get(org.plan, 0)
        if org_level < min_level:
            raise HTTPException(
                status_code=403,
                detail=f"This feature requires the '{minimum_plan}' plan or higher. "
                       f"Current plan: '{org.plan}'. Upgrade at POST /billing/checkout",
            )
        return auth
    return checker


def require_org(auth: AuthContext = Depends(verify_api_key_or_jwt)) -> AuthContext:
    """Dependency that requires the user to belong to an organization.

    API key users always have an org. JWT users must create one first.
    """
    if auth.org_id is None:
        raise HTTPException(
            status_code=403,
            detail="No organization found. Create one first: POST /v1/enterprise/orgs",
        )
    return auth
