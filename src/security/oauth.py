"""OAuth 2.0 provider implementations using only urllib (no extra dependencies).

Supports Google, Microsoft (Azure AD), and GitHub authorization code flow.
Each provider returns a normalized user profile: email, name, provider_id.
"""

import json
import logging
import secrets
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Optional

from src.config import get_settings

logger = logging.getLogger("governlayer")


@dataclass
class OAuthUserInfo:
    """Normalized user info returned by all OAuth providers."""
    email: str
    name: str
    provider: str
    provider_id: str


class OAuthError(Exception):
    """Raised when an OAuth flow step fails."""
    pass


def _http_post(url: str, data: dict, headers: Optional[dict] = None) -> dict:
    """POST form-encoded data and return parsed JSON response."""
    encoded = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(url, data=encoded, method="POST")
    req.add_header("Accept", "application/json")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        logger.error("OAuth HTTP POST failed: %s %s", url, exc)
        raise OAuthError(f"Token exchange failed: {exc}") from exc


def _http_get(url: str, headers: Optional[dict] = None) -> dict:
    """GET with headers and return parsed JSON response."""
    req = urllib.request.Request(url, method="GET")
    req.add_header("Accept", "application/json")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        logger.error("OAuth HTTP GET failed: %s %s", url, exc)
        raise OAuthError(f"User info request failed: {exc}") from exc


def generate_state() -> str:
    """Generate a cryptographically secure state parameter."""
    return secrets.token_urlsafe(32)


# ---------------------------------------------------------------------------
# Google OAuth 2.0
# ---------------------------------------------------------------------------

class GoogleOAuth:
    AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
    SCOPES = "openid email profile"

    @staticmethod
    def is_configured() -> bool:
        s = get_settings()
        return bool(s.google_client_id and s.google_client_secret)

    @staticmethod
    def get_authorize_url(state: str, redirect_uri: str) -> str:
        s = get_settings()
        params = {
            "client_id": s.google_client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": GoogleOAuth.SCOPES,
            "state": state,
            "access_type": "offline",
            "prompt": "consent",
        }
        return f"{GoogleOAuth.AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"

    @staticmethod
    def exchange_code(code: str, redirect_uri: str) -> dict:
        s = get_settings()
        return _http_post(GoogleOAuth.TOKEN_URL, {
            "client_id": s.google_client_id,
            "client_secret": s.google_client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        })

    @staticmethod
    def get_user_info(access_token: str) -> OAuthUserInfo:
        data = _http_get(GoogleOAuth.USERINFO_URL, {
            "Authorization": f"Bearer {access_token}",
        })
        return OAuthUserInfo(
            email=data.get("email", ""),
            name=data.get("name", data.get("email", "")),
            provider="google",
            provider_id=str(data.get("id", "")),
        )


# ---------------------------------------------------------------------------
# Microsoft / Azure AD OAuth 2.0
# ---------------------------------------------------------------------------

class MicrosoftOAuth:
    AUTHORIZE_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    USERINFO_URL = "https://graph.microsoft.com/v1.0/me"
    SCOPES = "openid email profile User.Read"

    @staticmethod
    def is_configured() -> bool:
        s = get_settings()
        return bool(s.microsoft_client_id and s.microsoft_client_secret)

    @staticmethod
    def get_authorize_url(state: str, redirect_uri: str) -> str:
        s = get_settings()
        params = {
            "client_id": s.microsoft_client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": MicrosoftOAuth.SCOPES,
            "state": state,
            "response_mode": "query",
        }
        return f"{MicrosoftOAuth.AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"

    @staticmethod
    def exchange_code(code: str, redirect_uri: str) -> dict:
        s = get_settings()
        return _http_post(MicrosoftOAuth.TOKEN_URL, {
            "client_id": s.microsoft_client_id,
            "client_secret": s.microsoft_client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
            "scope": MicrosoftOAuth.SCOPES,
        })

    @staticmethod
    def get_user_info(access_token: str) -> OAuthUserInfo:
        data = _http_get(MicrosoftOAuth.USERINFO_URL, {
            "Authorization": f"Bearer {access_token}",
        })
        email = data.get("mail") or data.get("userPrincipalName", "")
        name = data.get("displayName", email)
        return OAuthUserInfo(
            email=email,
            name=name,
            provider="microsoft",
            provider_id=str(data.get("id", "")),
        )


# ---------------------------------------------------------------------------
# GitHub OAuth 2.0
# ---------------------------------------------------------------------------

class GitHubOAuth:
    AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
    TOKEN_URL = "https://github.com/login/oauth/access_token"
    USER_URL = "https://api.github.com/user"
    EMAILS_URL = "https://api.github.com/user/emails"
    SCOPES = "read:user user:email"

    @staticmethod
    def is_configured() -> bool:
        s = get_settings()
        return bool(s.github_client_id and s.github_client_secret)

    @staticmethod
    def get_authorize_url(state: str, redirect_uri: str) -> str:
        s = get_settings()
        params = {
            "client_id": s.github_client_id,
            "redirect_uri": redirect_uri,
            "scope": GitHubOAuth.SCOPES,
            "state": state,
        }
        return f"{GitHubOAuth.AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"

    @staticmethod
    def exchange_code(code: str, redirect_uri: str) -> dict:
        s = get_settings()
        return _http_post(GitHubOAuth.TOKEN_URL, {
            "client_id": s.github_client_id,
            "client_secret": s.github_client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
        })

    @staticmethod
    def get_user_info(access_token: str) -> OAuthUserInfo:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "User-Agent": "GovernLayer-OAuth",
        }
        data = _http_get(GitHubOAuth.USER_URL, headers)

        email = data.get("email")
        if not email:
            # GitHub may not return email in profile; fetch from emails endpoint
            try:
                emails = _http_get(GitHubOAuth.EMAILS_URL, headers)
                for entry in emails:
                    if entry.get("primary") and entry.get("verified"):
                        email = entry["email"]
                        break
                if not email and emails:
                    email = emails[0].get("email", "")
            except OAuthError:
                email = ""

        return OAuthUserInfo(
            email=email or "",
            name=data.get("name") or data.get("login", ""),
            provider="github",
            provider_id=str(data.get("id", "")),
        )


# ---------------------------------------------------------------------------
# Provider registry
# ---------------------------------------------------------------------------

PROVIDERS = {
    "google": GoogleOAuth,
    "microsoft": MicrosoftOAuth,
    "github": GitHubOAuth,
}


def get_provider(name: str):
    """Return the OAuth provider class by name, or None if unknown."""
    return PROVIDERS.get(name.lower())


def list_configured_providers() -> list[str]:
    """Return names of providers that have client credentials configured."""
    return [name for name, cls in PROVIDERS.items() if cls.is_configured()]
