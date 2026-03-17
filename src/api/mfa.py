"""Multi-Factor Authentication — TOTP (Google Authenticator compatible)."""

import hashlib
import io
import json
import secrets
from base64 import b64encode

import pyotp
import qrcode
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.models.database import User, get_db
from src.security.auth import verify_token

router = APIRouter(prefix="/auth/mfa", tags=["MFA"])


class MFASetupResponse(BaseModel):
    secret: str
    provisioning_uri: str
    qr_code_base64: str
    backup_codes: list[str]


class MFAVerifyRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")


class MFADisableRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=8)  # 6 for TOTP, 8 for backup


@router.post("/setup")
def setup_mfa(email: str = Depends(verify_token), db: Session = Depends(get_db)):
    """Generate TOTP secret and QR code for authenticator app setup."""
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is already enabled. Disable it first to reconfigure.")

    # Generate TOTP secret
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=email, issuer_name="GovernLayer")

    # Generate QR code as base64
    img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = b64encode(buf.getvalue()).decode()

    # Generate backup codes (10 codes, 8 chars each)
    backup_codes = [secrets.token_hex(4).upper() for _ in range(10)]
    hashed_codes = [hashlib.sha256(c.encode()).hexdigest() for c in backup_codes]

    # Store secret and backup codes (not yet enabled — needs verify step)
    user.mfa_secret = secret
    user.mfa_backup_codes = json.dumps(hashed_codes)
    db.commit()

    return {
        "secret": secret,
        "provisioning_uri": provisioning_uri,
        "qr_code_base64": qr_b64,
        "backup_codes": backup_codes,
        "message": "Scan the QR code with your authenticator app, then verify with POST /auth/mfa/verify to enable MFA.",
    }


@router.post("/verify")
def verify_and_enable_mfa(req: MFAVerifyRequest, email: str = Depends(verify_token),
                          db: Session = Depends(get_db)):
    """Verify TOTP code and enable MFA. Must be called after /setup."""
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.mfa_secret:
        raise HTTPException(status_code=400, detail="Run /auth/mfa/setup first")
    if user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is already enabled")

    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(req.code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid code. Check your authenticator app and try again.")

    user.mfa_enabled = True
    db.commit()
    return {"message": "MFA enabled successfully.", "mfa_enabled": True}


@router.post("/disable")
def disable_mfa(req: MFADisableRequest, email: str = Depends(verify_token),
                db: Session = Depends(get_db)):
    """Disable MFA. Requires a valid TOTP code or backup code."""
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled")

    # Check TOTP code
    totp = pyotp.TOTP(user.mfa_secret)
    if totp.verify(req.code, valid_window=1):
        user.mfa_enabled = False
        user.mfa_secret = None
        user.mfa_backup_codes = None
        db.commit()
        return {"message": "MFA disabled.", "mfa_enabled": False}

    # Check backup codes
    if _use_backup_code(user, req.code, db):
        user.mfa_enabled = False
        user.mfa_secret = None
        user.mfa_backup_codes = None
        db.commit()
        return {"message": "MFA disabled via backup code.", "mfa_enabled": False}

    raise HTTPException(status_code=400, detail="Invalid code")


@router.get("/status")
def mfa_status(email: str = Depends(verify_token), db: Session = Depends(get_db)):
    """Check if MFA is enabled for the current user."""
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"mfa_enabled": user.mfa_enabled, "email": email}


def verify_mfa_code(user: User, code: str, db: Session) -> bool:
    """Verify a TOTP code or backup code. Used by login flow."""
    if not user.mfa_enabled or not user.mfa_secret:
        return True  # MFA not enabled, always pass

    totp = pyotp.TOTP(user.mfa_secret)
    if totp.verify(code, valid_window=1):
        return True

    return _use_backup_code(user, code, db)


def _use_backup_code(user: User, code: str, db: Session) -> bool:
    """Check and consume a backup code."""
    if not user.mfa_backup_codes:
        return False
    codes = json.loads(user.mfa_backup_codes)
    code_hash = hashlib.sha256(code.upper().encode()).hexdigest()
    if code_hash in codes:
        codes.remove(code_hash)
        user.mfa_backup_codes = json.dumps(codes)
        db.commit()
        return True
    return False
