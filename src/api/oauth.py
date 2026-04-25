"""OAuth 2.0 / SSO endpoints for enterprise customers.

Supports Google, Microsoft (Azure AD), and GitHub login.
Gracefully returns 501 if a provider is not configured (missing client_id/secret).
"""

import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.config import get_settings
from src.models.database import User, get_db
from src.security.auth import create_token, verify_token
from src.security.oauth import (
    OAuthError,
    generate_state,
    get_provider,
    list_configured_providers,
)

logger = logging.getLogger("governlayer")

router = APIRouter(prefix="/auth/oauth", tags=["OAuth"])


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class OAuthCallbackRequest(BaseModel):
    code: str = Field(..., description="Authorization code from the OAuth provider")
    state: str = Field("", description="State parameter for CSRF verification")
    redirect_uri: str = Field("", description="Redirect URI used in the authorize step")


class OAuthAuthorizeResponse(BaseModel):
    authorize_url: str
    state: str
    provider: str


class OAuthTokenResponse(BaseModel):
    token: str
    email: str
    provider: str
    is_new_user: bool


class OAuthProviderInfo(BaseModel):
    name: str
    configured: bool


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_redirect_uri(provider_name: str, explicit_uri: str = "") -> str:
    """Build the OAuth redirect URI for a given provider."""
    if explicit_uri:
        return explicit_uri
    settings = get_settings()
    base = settings.oauth_redirect_base.rstrip("/")
    if not base:
        base = f"http://localhost:{settings.port}"
    return f"{base}/auth/oauth/{provider_name}/callback"


def _get_or_create_oauth_user(
    db: Session, email: str, name: str, provider: str, provider_id: str
) -> tuple[User, bool]:
    """Find existing user by email or OAuth provider ID, or create a new one.

    Returns (user, is_new_user).
    """
    # First try to find by OAuth provider + provider_id
    user = db.query(User).filter(
        User.oauth_provider == provider,
        User.oauth_provider_id == provider_id,
    ).first()
    if user:
        return user, False

    # Then try by email
    user = db.query(User).filter(User.email == email).first()
    if user:
        # Link this OAuth provider to the existing account
        if not user.oauth_provider:
            user.oauth_provider = provider
            user.oauth_provider_id = provider_id
        # OAuth login proves email ownership — auto-verify
        if not user.email_verified:
            user.email_verified = True
            user.verification_token = None
        _add_linked_provider(user, provider, provider_id)
        db.commit()
        return user, False

    # Create new user (no password — OAuth-only account)
    company = name or email.split("@")[0]
    user = User(
        email=email,
        password_hash="OAUTH_NO_PASSWORD",
        company=company,
        email_verified=True,  # OAuth provider already verified the email
        oauth_provider=provider,
        oauth_provider_id=provider_id,
        oauth_linked_providers=json.dumps([{
            "provider": provider,
            "provider_id": provider_id,
        }]),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user, True


def _add_linked_provider(user: User, provider: str, provider_id: str) -> None:
    """Add a provider to the user's linked_providers JSON list."""
    existing = []
    if user.oauth_linked_providers:
        try:
            existing = json.loads(user.oauth_linked_providers)
        except (json.JSONDecodeError, TypeError):
            existing = []
    # Avoid duplicates
    for entry in existing:
        if entry.get("provider") == provider:
            entry["provider_id"] = provider_id
            user.oauth_linked_providers = json.dumps(existing)
            return
    existing.append({"provider": provider, "provider_id": provider_id})
    user.oauth_linked_providers = json.dumps(existing)


def _remove_linked_provider(user: User, provider: str) -> bool:
    """Remove a provider from the user's linked_providers JSON list.

    Returns True if removed, False if not found.
    """
    existing = []
    if user.oauth_linked_providers:
        try:
            existing = json.loads(user.oauth_linked_providers)
        except (json.JSONDecodeError, TypeError):
            existing = []
    original_len = len(existing)
    existing = [e for e in existing if e.get("provider") != provider]
    if len(existing) == original_len:
        return False
    user.oauth_linked_providers = json.dumps(existing) if existing else None
    # Clear primary OAuth fields if this was the primary provider
    if user.oauth_provider == provider:
        user.oauth_provider = None
        user.oauth_provider_id = None
        # Promote next linked provider if available
        if existing:
            user.oauth_provider = existing[0]["provider"]
            user.oauth_provider_id = existing[0]["provider_id"]
    return True


def _auto_provision_org(db: Session, user: User) -> None:
    """Auto-create an org for new OAuth users so they can start immediately.

    Creates an org with a slug derived from their company/name, adds them as owner,
    and generates a default API key. This eliminates manual onboarding steps.
    """
    import re
    from src.models.tenant import ApiKey, OrgMembership, Organization, generate_api_key

    # Build a slug from company name
    raw_slug = re.sub(r"[^a-z0-9-]", "-", user.company.lower()).strip("-")
    raw_slug = re.sub(r"-+", "-", raw_slug) or "my-org"
    slug = raw_slug

    # Ensure uniqueness
    counter = 1
    while db.query(Organization).filter(Organization.slug == slug).first():
        slug = f"{raw_slug}-{counter}"
        counter += 1

    org = Organization(name=user.company, slug=slug, plan="free")
    db.add(org)
    db.flush()

    membership = OrgMembership(user_email=user.email, org_id=org.id, role="owner")
    db.add(membership)

    # Auto-generate a default API key
    full_key, prefix, key_hash = generate_api_key()
    api_key = ApiKey(
        org_id=org.id, name="default", key_prefix=prefix,
        key_hash=key_hash, scopes="govern,audit,risk,scan,read",
    )
    db.add(api_key)
    db.commit()

    logger.info(
        "Auto-provisioned org '%s' (slug=%s) with API key %s... for %s",
        org.name, slug, prefix, user.email,
    )

    # Notify about the API key
    try:
        from src.email.service import send_api_key_created
        send_api_key_created(user.email, prefix)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/providers", response_model=list[OAuthProviderInfo])
def list_providers():
    """List all OAuth providers and whether they are configured."""
    all_providers = ["google", "microsoft", "github"]
    configured = set(list_configured_providers())
    return [
        OAuthProviderInfo(name=p, configured=(p in configured))
        for p in all_providers
    ]


@router.get("/{provider}/authorize", response_model=OAuthAuthorizeResponse)
def authorize(provider: str):
    """Get the authorization URL for an OAuth provider.

    Redirect the user's browser to the returned URL to begin the OAuth flow.
    """
    provider_cls = get_provider(provider)
    if not provider_cls:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")
    if not provider_cls.is_configured():
        raise HTTPException(
            status_code=501,
            detail=f"Provider not configured: {provider}. Set {provider.upper()}_CLIENT_ID and {provider.upper()}_CLIENT_SECRET.",
        )
    state = generate_state()
    redirect_uri = _get_redirect_uri(provider)
    url = provider_cls.get_authorize_url(state, redirect_uri)
    return OAuthAuthorizeResponse(authorize_url=url, state=state, provider=provider)


@router.post("/{provider}/callback", response_model=OAuthTokenResponse)
def callback(provider: str, body: OAuthCallbackRequest, db: Session = Depends(get_db)):
    """Exchange an authorization code for a JWT token.

    This endpoint:
    1. Exchanges the code with the OAuth provider for an access token
    2. Fetches the user's profile (email, name, provider ID)
    3. Creates or links the user account
    4. Returns a GovernLayer JWT
    """
    provider_cls = get_provider(provider)
    if not provider_cls:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")
    if not provider_cls.is_configured():
        raise HTTPException(
            status_code=501,
            detail=f"Provider not configured: {provider}",
        )

    redirect_uri = body.redirect_uri or _get_redirect_uri(provider)

    # Exchange code for tokens
    try:
        token_data = provider_cls.exchange_code(body.code, redirect_uri)
    except OAuthError as exc:
        logger.warning("OAuth token exchange failed for %s: %s", provider, exc)
        raise HTTPException(status_code=400, detail=f"Token exchange failed: {exc}")

    access_token = token_data.get("access_token")
    if not access_token:
        error = token_data.get("error_description") or token_data.get("error", "unknown")
        raise HTTPException(status_code=400, detail=f"No access token received: {error}")

    # Fetch user info
    try:
        user_info = provider_cls.get_user_info(access_token)
    except OAuthError as exc:
        logger.warning("OAuth user info failed for %s: %s", provider, exc)
        raise HTTPException(status_code=400, detail=f"Failed to fetch user info: {exc}")

    if not user_info.email:
        raise HTTPException(
            status_code=400,
            detail="OAuth provider did not return an email address. Ensure your account has a verified email.",
        )

    # Create or link user
    user, is_new = _get_or_create_oauth_user(
        db, user_info.email, user_info.name, user_info.provider, user_info.provider_id
    )

    jwt_token = create_token(user.email)
    logger.info(
        "OAuth login: provider=%s email=%s new_user=%s",
        provider, user.email, is_new,
    )

    # For new OAuth users: auto-create org + send welcome email
    if is_new:
        _auto_provision_org(db, user)
        try:
            from src.email.service import send_welcome_email
            send_welcome_email(user.email, user.company)
        except Exception:
            pass  # Don't block login if email fails

    return OAuthTokenResponse(
        token=jwt_token,
        email=user.email,
        provider=provider,
        is_new_user=is_new,
    )


@router.post("/link/{provider}")
def link_provider(
    provider: str,
    body: OAuthCallbackRequest,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    """Link an OAuth provider to an existing authenticated account.

    Requires a valid JWT. The user must complete the OAuth flow and provide
    the authorization code here.
    """
    provider_cls = get_provider(provider)
    if not provider_cls:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")
    if not provider_cls.is_configured():
        raise HTTPException(status_code=501, detail=f"Provider not configured: {provider}")

    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    redirect_uri = body.redirect_uri or _get_redirect_uri(provider)

    # Exchange code
    try:
        token_data = provider_cls.exchange_code(body.code, redirect_uri)
    except OAuthError as exc:
        raise HTTPException(status_code=400, detail=f"Token exchange failed: {exc}")

    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(status_code=400, detail="No access token received")

    # Fetch user info
    try:
        user_info = provider_cls.get_user_info(access_token)
    except OAuthError as exc:
        raise HTTPException(status_code=400, detail=f"Failed to fetch user info: {exc}")

    # Check if this provider account is already linked to another user
    existing = db.query(User).filter(
        User.oauth_provider == provider,
        User.oauth_provider_id == user_info.provider_id,
        User.id != user.id,
    ).first()
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"This {provider} account is already linked to another user.",
        )

    # Link
    if not user.oauth_provider:
        user.oauth_provider = provider
        user.oauth_provider_id = user_info.provider_id
    _add_linked_provider(user, provider, user_info.provider_id)
    db.commit()

    logger.info("OAuth link: provider=%s email=%s", provider, email)
    return {
        "message": f"Successfully linked {provider} account",
        "provider": provider,
        "provider_email": user_info.email,
    }


@router.delete("/unlink/{provider}")
def unlink_provider(
    provider: str,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    """Unlink an OAuth provider from the current account.

    The user must have a password set or at least one other linked provider
    to avoid being locked out.
    """
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Safety: don't let user lock themselves out
    has_password = user.password_hash and user.password_hash != "OAUTH_NO_PASSWORD"
    linked = []
    if user.oauth_linked_providers:
        try:
            linked = json.loads(user.oauth_linked_providers)
        except (json.JSONDecodeError, TypeError):
            linked = []
    other_providers = [e for e in linked if e.get("provider") != provider]

    if not has_password and not other_providers:
        raise HTTPException(
            status_code=400,
            detail="Cannot unlink the only authentication method. Set a password first or link another provider.",
        )

    removed = _remove_linked_provider(user, provider)
    if not removed:
        raise HTTPException(status_code=404, detail=f"Provider {provider} is not linked to your account")

    db.commit()
    logger.info("OAuth unlink: provider=%s email=%s", provider, email)
    return {"message": f"Successfully unlinked {provider}", "provider": provider}
