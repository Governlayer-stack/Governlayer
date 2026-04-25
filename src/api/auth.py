import logging
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from src.models.database import User, get_db
from src.models.schemas import ForgotPasswordRequest, ResetPasswordRequest, UserLogin, UserRegister
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from src.security.auth import create_token, decode_token_payload, hash_password, revoke_token, verify_password

_security = HTTPBearer()

logger = logging.getLogger("governlayer")

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register")
def register(user: UserRegister, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == user.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    verification_token = secrets.token_hex(32)
    new_user = User(
        email=user.email, password_hash=hash_password(user.password),
        company=user.company, verification_token=verification_token,
    )
    db.add(new_user)
    db.commit()
    token = create_token(user.email)
    from src.email.service import send_welcome_email, send_verification_email
    send_welcome_email(user.email, user.company)
    send_verification_email(user.email, verification_token)
    return {"message": f"Welcome to GovernLayer {user.company}", "token": token, "email": user.email, "email_verified": False}


@router.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Check MFA
    if db_user.mfa_enabled:
        if not user.mfa_code:
            return {"mfa_required": True, "message": "MFA code required. Include mfa_code in request body."}
        from src.api.mfa import verify_mfa_code
        if not verify_mfa_code(db_user, user.mfa_code, db):
            raise HTTPException(status_code=401, detail="Invalid MFA code")

    return {"token": create_token(user.email), "email": user.email, "email_verified": db_user.email_verified}


@router.post("/verify-email")
def verify_email(token: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.verification_token == token).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired verification token")
    user.email_verified = True
    user.verification_token = None
    db.commit()
    return {"message": "Email verified successfully", "email": user.email}


@router.post("/resend-verification")
def resend_verification(credentials: HTTPAuthorizationCredentials = Depends(_security), db: Session = Depends(get_db)):
    payload = decode_token_payload(credentials.credentials)
    email = payload.get("sub")
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.email_verified:
        return {"message": "Email already verified"}
    token = secrets.token_hex(32)
    user.verification_token = token
    db.commit()
    from src.email.service import send_verification_email
    send_verification_email(email, token)
    return {"message": "Verification email sent"}


@router.post("/forgot-password")
def forgot_password(req: ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if user:
        token = secrets.token_hex(32)
        user.reset_token = token
        user.reset_token_expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        db.commit()
        logger.debug("Password reset requested for %s", req.email)
        from src.email.service import send_password_reset
        send_password_reset(req.email, token)
    return {"message": "If an account exists with that email, a reset link has been sent."}


@router.post("/reset-password")
def reset_password(req: ResetPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(
        User.reset_token == req.token,
        User.reset_token_expires_at > datetime.now(timezone.utc),
    ).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    user.password_hash = hash_password(req.new_password)
    user.reset_token = None
    user.reset_token_expires_at = None
    db.commit()
    return {"message": "Password reset successfully. Please log in."}


@router.get("/onboarding-status")
def onboarding_status(credentials: HTTPAuthorizationCredentials = Depends(_security), db: Session = Depends(get_db)):
    """Check where the user is in the onboarding flow."""
    payload = decode_token_payload(credentials.credentials)
    email = payload.get("sub")
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    from src.models.tenant import OrgMembership, Organization, ApiKey
    membership = db.query(OrgMembership).filter(OrgMembership.user_email == email).first()
    org = None
    has_api_key = False
    if membership:
        org = db.query(Organization).filter(Organization.id == membership.org_id).first()
        if org:
            has_api_key = db.query(ApiKey).filter(
                ApiKey.org_id == org.id, ApiKey.is_active.is_(True)
            ).count() > 0

    steps = {
        "account_created": True,
        "email_verified": user.email_verified,
        "org_created": org is not None,
        "api_key_generated": has_api_key,
        "mfa_enabled": user.mfa_enabled,
    }
    completed = sum(1 for v in steps.values() if v)
    total = len(steps)

    # Next action hint
    if not user.email_verified:
        next_step = {"action": "Verify your email", "endpoint": "POST /auth/verify-email", "hint": "Check your inbox for the verification link"}
    elif org is None:
        next_step = {"action": "Create your organization", "endpoint": "POST /v1/enterprise/orgs", "hint": "This isolates your data into your own tenant"}
    elif not has_api_key:
        next_step = {"action": "Generate an API key", "endpoint": f"POST /v1/enterprise/orgs/{org.slug}/api-keys", "hint": "Use the API key for programmatic access"}
    elif not user.mfa_enabled:
        next_step = {"action": "Enable MFA (recommended)", "endpoint": "POST /auth/mfa/setup", "hint": "Adds a second factor for account security"}
    else:
        next_step = {"action": "You're all set!", "endpoint": "GET /v1/dashboard", "hint": "Start governing your AI systems"}

    return {
        "email": email,
        "company": user.company,
        "progress": f"{completed}/{total}",
        "complete": completed == total,
        "steps": steps,
        "next_step": next_step,
        "org": {"name": org.name, "slug": org.slug, "plan": org.plan} if org else None,
    }


@router.post("/logout")
def logout(credentials: HTTPAuthorizationCredentials = Depends(_security)):
    """Invalidate the current JWT token."""
    payload = decode_token_payload(credentials.credentials)
    jti = payload.get("jti")
    if not jti:
        raise HTTPException(status_code=400, detail="Token does not support revocation")
    exp = payload.get("exp")
    revoke_token(jti, exp)
    return {"message": "Successfully logged out"}
