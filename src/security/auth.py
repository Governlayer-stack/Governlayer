from datetime import datetime, timedelta

import bcrypt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from src.config import get_settings

settings = get_settings()
security = HTTPBearer()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password[:72].encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password[:72].encode(), hashed.encode())


def create_token(email: str) -> str:
    expire = datetime.utcnow() + timedelta(hours=settings.jwt_expiry_hours)
    return jwt.encode({"sub": email, "exp": expire}, settings.secret_key, algorithm=settings.jwt_algorithm)


def verify_token_raw(token: str) -> str:
    """Verify a JWT token string directly (used by API key auth fallback)."""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return email
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    return verify_token_raw(credentials.credentials)
