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
    new_user = User(email=user.email, password_hash=hash_password(user.password), company=user.company)
    db.add(new_user)
    db.commit()
    token = create_token(user.email)
    from src.email.service import send_welcome_email
    send_welcome_email(user.email, user.company)
    return {"message": f"Welcome to GovernLayer {user.company}", "token": token, "email": user.email}


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

    return {"token": create_token(user.email), "email": user.email}


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
