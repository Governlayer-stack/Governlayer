import logging
import threading
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from jwt.exceptions import PyJWTError

from src.config import get_settings

logger = logging.getLogger(__name__)

settings = get_settings()
security = HTTPBearer()

# In-memory token blacklist (fallback): {jti: expiry_timestamp}
_token_blacklist: dict[str, float] = {}
_blacklist_lock = threading.Lock()

# Lazy Redis connection
_redis_client = None
_redis_available: bool | None = None  # None = not yet checked


def _get_redis():
    """Lazy Redis connection. Returns the client or None if unavailable."""
    global _redis_client, _redis_available

    if _redis_available is False:
        return None

    if _redis_client is not None:
        return _redis_client

    try:
        import redis
        client = redis.from_url(settings.redis_url, decode_responses=True, socket_connect_timeout=2)
        client.ping()
        _redis_client = client
        _redis_available = True
        logger.info("Token blacklist using Redis at %s", settings.redis_url)
        return _redis_client
    except Exception:
        _redis_available = False
        logger.warning("Redis unavailable for token blacklist, falling back to in-memory store")
        return None


def _cleanup_blacklist() -> None:
    """Remove expired entries from the in-memory blacklist."""
    now = datetime.now(timezone.utc).timestamp()
    with _blacklist_lock:
        expired = [jti for jti, exp in _token_blacklist.items() if exp < now]
        for jti in expired:
            del _token_blacklist[jti]


def revoke_token(jti: str, exp: float | None = None) -> None:
    """Add a token's jti to the blacklist. exp is the token's expiry as a unix timestamp."""
    if exp is None:
        exp = (datetime.now(timezone.utc) + timedelta(hours=settings.jwt_expiry_hours)).timestamp()

    r = _get_redis()
    if r is not None:
        try:
            ttl_seconds = max(int(exp - datetime.now(timezone.utc).timestamp()), 1)
            r.set(f"revoked:{jti}", "1", ex=ttl_seconds)
            return
        except Exception:
            logger.warning("Redis write failed for token revocation, falling back to in-memory")

    # Fallback: in-memory
    with _blacklist_lock:
        _token_blacklist[jti] = exp
    if len(_token_blacklist) > 1000:
        _cleanup_blacklist()


def is_token_revoked(jti: str) -> bool:
    """Check if a token has been revoked."""
    r = _get_redis()
    if r is not None:
        try:
            return r.exists(f"revoked:{jti}") > 0
        except Exception:
            logger.warning("Redis read failed for token check, falling back to in-memory")

    # Fallback: in-memory
    with _blacklist_lock:
        return jti in _token_blacklist


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password[:72].encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password[:72].encode(), hashed.encode())


def create_token(email: str) -> str:
    jti = str(uuid.uuid4())
    iat = datetime.now(timezone.utc)
    expire = iat + timedelta(hours=settings.jwt_expiry_hours)
    return jwt.encode(
        {"sub": email, "exp": expire, "iat": iat, "jti": jti},
        settings.secret_key,
        algorithm=settings.jwt_algorithm,
    )


def verify_token_raw(token: str) -> str:
    """Verify a JWT token string directly (used by API key auth fallback)."""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        jti = payload.get("jti")
        if jti and is_token_revoked(jti):
            raise HTTPException(status_code=401, detail="Token has been revoked")
        return email
    except PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def decode_token_payload(token: str) -> dict:
    """Decode a JWT and return the full payload. Raises HTTPException on failure."""
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
    except PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    return verify_token_raw(credentials.credentials)


def verify_token_verified(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """Verify JWT and require email to be verified. Returns email."""
    from src.models.database import get_db, User, SessionLocal
    email = verify_token_raw(credentials.credentials)
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        if not user.email_verified:
            raise HTTPException(
                status_code=403,
                detail="Email not verified. Check your inbox or POST /auth/resend-verification",
            )
        return email
    finally:
        db.close()
