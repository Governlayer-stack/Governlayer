"""SAML 2.0 / OIDC Single Sign-On API for enterprise IdP integration.

Supports Okta, Azure AD, Google Workspace, OneLogin, JumpCloud, and custom
SAML/OIDC identity providers.  Configuration is stored in-memory (keyed by
org_id).  The SAML ACS endpoint performs a lightweight XML parse to extract
the NameID -- full signature validation is left to a production SAML library.

No external dependencies beyond FastAPI, Pydantic, and the Python stdlib
(xml.etree.ElementTree, base64, urllib).
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel, Field

from src.config import get_settings
from src.security.auth import create_token, verify_token

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter(prefix="/v1/sso", tags=["SSO"])

# ---------------------------------------------------------------------------
# In-memory SSO configuration store  {org_id -> [SSOConfigEntry, ...]}
# ---------------------------------------------------------------------------

_sso_configs: dict[str, list[dict[str, Any]]] = {}

# Pending OIDC authorization states  {state -> {config_id, nonce, created_at}}
_oidc_pending_states: dict[str, dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# Enums & Pydantic models
# ---------------------------------------------------------------------------

class ProviderType(str, Enum):
    saml = "saml"
    oidc = "oidc"


class SSOStatus(str, Enum):
    inactive = "inactive"
    active = "active"
    testing = "testing"


class SSOConfigureRequest(BaseModel):
    provider_type: ProviderType
    provider_name: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Human-readable IdP name, e.g. 'Okta', 'Azure AD', 'Google Workspace'.",
    )
    config: dict[str, Any] = Field(
        ...,
        description=(
            "Provider-specific fields.  "
            "SAML: entity_id, sso_url, slo_url (opt), certificate, name_id_format.  "
            "OIDC: client_id, client_secret, authorization_url, token_url, userinfo_url, scopes."
        ),
    )
    domain_whitelist: list[str] = Field(
        default_factory=list,
        description="Email domains that map to this SSO config (e.g. ['acme.com']).",
    )
    enforce: bool = Field(
        default=False,
        description="When True, users whose email matches domain_whitelist MUST authenticate via SSO.",
    )


class SSOConfigResponse(BaseModel):
    id: str
    org_id: str
    provider_type: str
    provider_name: str
    status: str
    config: dict[str, Any]
    domain_whitelist: list[str]
    enforce: bool
    created_at: str
    updated_at: str
    created_by: str


class SAMLResponsePayload(BaseModel):
    SAMLResponse: str = Field(..., description="Base64-encoded SAML Response XML from the IdP.")
    RelayState: str | None = Field(default=None, description="Optional relay state for redirect.")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAML_REQUIRED_FIELDS = {"entity_id", "sso_url", "certificate", "name_id_format"}
OIDC_REQUIRED_FIELDS = {"client_id", "client_secret", "authorization_url", "token_url", "userinfo_url"}

SP_ENTITY_ID = "https://api.governlayer.ai/v1/sso"
SP_ACS_URL = "https://api.governlayer.ai/v1/sso/saml/acs"
SP_OIDC_CALLBACK_URL = "https://api.governlayer.ai/v1/sso/oidc/callback"


def _get_config_by_id(config_id: str) -> dict[str, Any] | None:
    """Look up a single SSO config across all orgs."""
    for configs in _sso_configs.values():
        for cfg in configs:
            if cfg["id"] == config_id:
                return cfg
    return None


def _redact_secrets(config: dict[str, Any], provider_type: str) -> dict[str, Any]:
    """Return a copy of the provider config with secrets masked."""
    redacted = dict(config)
    if provider_type == "oidc" and "client_secret" in redacted:
        secret = redacted["client_secret"]
        redacted["client_secret"] = secret[:4] + "****" + secret[-4:] if len(secret) > 8 else "****"
    if provider_type == "saml" and "certificate" in redacted:
        cert = redacted["certificate"]
        redacted["certificate"] = cert[:40] + "...[REDACTED]" if len(cert) > 40 else "[REDACTED]"
    return redacted


def _serialize_config(cfg: dict[str, Any], *, redact: bool = True) -> dict[str, Any]:
    """Serialize an SSO config entry for API responses."""
    provider_config = _redact_secrets(cfg["config"], cfg["provider_type"]) if redact else cfg["config"]
    return {
        "id": cfg["id"],
        "org_id": cfg["org_id"],
        "provider_type": cfg["provider_type"],
        "provider_name": cfg["provider_name"],
        "status": cfg["status"],
        "config": provider_config,
        "domain_whitelist": cfg["domain_whitelist"],
        "enforce": cfg["enforce"],
        "created_at": cfg["created_at"],
        "updated_at": cfg["updated_at"],
        "created_by": cfg["created_by"],
    }


def _validate_config_fields(provider_type: str, config: dict[str, Any]) -> list[str]:
    """Return a list of missing required fields for the given provider type."""
    required = SAML_REQUIRED_FIELDS if provider_type == "saml" else OIDC_REQUIRED_FIELDS
    return [f for f in required if not config.get(f)]


def _org_id_for_user(email: str) -> str:
    """Derive a deterministic org identifier from the user's email domain.

    In a full implementation this would query the Organization table.  For the
    in-memory SSO store we use a stable hash of the domain so that all users
    in the same domain share configurations.
    """
    domain = email.split("@")[-1] if "@" in email else email
    return hashlib.sha256(domain.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# 1. GET "" -- List SSO configurations for the caller's org
# ---------------------------------------------------------------------------

@router.get("")
def list_sso_configs(email: str = Depends(verify_token)):
    """List all SSO configurations for the authenticated user's organization."""
    org_id = _org_id_for_user(email)
    configs = _sso_configs.get(org_id, [])
    return {
        "org_id": org_id,
        "total": len(configs),
        "configs": [_serialize_config(c) for c in configs],
    }


# ---------------------------------------------------------------------------
# 2. POST "/configure" -- Create or update SSO configuration
# ---------------------------------------------------------------------------

@router.post("/configure")
def configure_sso(req: SSOConfigureRequest, email: str = Depends(verify_token)):
    """Create or update an SSO configuration for the authenticated user's org.

    If an active configuration already exists for the same provider_type it will
    be replaced (the old config is removed).
    """
    org_id = _org_id_for_user(email)
    now = datetime.now(timezone.utc).isoformat()

    # Validate provider-specific required fields
    missing = _validate_config_fields(req.provider_type.value, req.config)
    if missing:
        raise HTTPException(
            status_code=422,
            detail=f"Missing required config fields for {req.provider_type.value}: {', '.join(missing)}",
        )

    # Normalise domain whitelist to lowercase
    domains = [d.lower().strip() for d in req.domain_whitelist if d.strip()]

    # Build the config entry
    config_entry: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "org_id": org_id,
        "provider_type": req.provider_type.value,
        "provider_name": req.provider_name,
        "status": SSOStatus.inactive.value,
        "config": req.config,
        "domain_whitelist": domains,
        "enforce": req.enforce,
        "created_at": now,
        "updated_at": now,
        "created_by": email,
    }

    # Upsert: remove any existing config of the same type for this org
    if org_id not in _sso_configs:
        _sso_configs[org_id] = []
    _sso_configs[org_id] = [
        c for c in _sso_configs[org_id] if c["provider_type"] != req.provider_type.value
    ]
    _sso_configs[org_id].append(config_entry)

    logger.info(
        "SSO configured: org=%s type=%s provider=%s id=%s",
        org_id, req.provider_type.value, req.provider_name, config_entry["id"],
    )

    return {
        "message": f"SSO configuration created for {req.provider_name}.",
        "config": _serialize_config(config_entry),
        "next_steps": [
            f"Upload the SP metadata to your IdP: GET /v1/sso/saml/metadata/{config_entry['id']}"
            if req.provider_type == ProviderType.saml
            else f"Register the callback URL in your IdP: {SP_OIDC_CALLBACK_URL}",
            f"Test the configuration: POST /v1/sso/{config_entry['id']}/test",
            f"Activate when ready: POST /v1/sso/{config_entry['id']}/activate",
        ],
    }


# ---------------------------------------------------------------------------
# 3. GET "/{config_id}" -- Get SSO config details
# ---------------------------------------------------------------------------

@router.get("/{config_id}")
def get_sso_config(config_id: str, email: str = Depends(verify_token)):
    """Retrieve a specific SSO configuration by its ID."""
    cfg = _get_config_by_id(config_id)
    if cfg is None:
        raise HTTPException(status_code=404, detail="SSO configuration not found")
    # Verify the caller belongs to the same org
    caller_org = _org_id_for_user(email)
    if cfg["org_id"] != caller_org:
        raise HTTPException(status_code=403, detail="Access denied to this SSO configuration")
    return _serialize_config(cfg)


# ---------------------------------------------------------------------------
# 4. DELETE "/{config_id}" -- Remove SSO configuration
# ---------------------------------------------------------------------------

@router.delete("/{config_id}")
def delete_sso_config(config_id: str, email: str = Depends(verify_token)):
    """Delete an SSO configuration.  Active configs must be deactivated first."""
    cfg = _get_config_by_id(config_id)
    if cfg is None:
        raise HTTPException(status_code=404, detail="SSO configuration not found")
    caller_org = _org_id_for_user(email)
    if cfg["org_id"] != caller_org:
        raise HTTPException(status_code=403, detail="Access denied to this SSO configuration")
    if cfg["status"] == SSOStatus.active.value:
        raise HTTPException(
            status_code=409,
            detail="Cannot delete an active SSO configuration. Deactivate it first.",
        )

    _sso_configs[caller_org] = [c for c in _sso_configs.get(caller_org, []) if c["id"] != config_id]
    logger.info("SSO config deleted: id=%s org=%s by=%s", config_id, caller_org, email)
    return {"message": "SSO configuration deleted", "id": config_id}


# ---------------------------------------------------------------------------
# 5. POST "/{config_id}/test" -- Validate config (simulated)
# ---------------------------------------------------------------------------

@router.post("/{config_id}/test")
def test_sso_config(config_id: str, email: str = Depends(verify_token)):
    """Run a simulated validation of the SSO configuration.

    Checks that all required fields are present and well-formed.  Does not
    perform a live IdP handshake (that requires browser-based auth).
    """
    cfg = _get_config_by_id(config_id)
    if cfg is None:
        raise HTTPException(status_code=404, detail="SSO configuration not found")
    caller_org = _org_id_for_user(email)
    if cfg["org_id"] != caller_org:
        raise HTTPException(status_code=403, detail="Access denied to this SSO configuration")

    provider_type = cfg["provider_type"]
    provider_config = cfg["config"]
    checklist: list[dict[str, Any]] = []

    if provider_type == "saml":
        # SAML checks
        checklist.append({
            "check": "entity_id_present",
            "label": "IdP Entity ID is configured",
            "passed": bool(provider_config.get("entity_id")),
        })
        checklist.append({
            "check": "sso_url_valid",
            "label": "SSO URL is a valid HTTPS endpoint",
            "passed": (provider_config.get("sso_url", "")).startswith("https://"),
        })
        checklist.append({
            "check": "certificate_present",
            "label": "X.509 signing certificate is present",
            "passed": bool(provider_config.get("certificate")),
        })
        checklist.append({
            "check": "certificate_looks_valid",
            "label": "Certificate contains BEGIN/END markers or is base64-encoded",
            "passed": (
                "BEGIN CERTIFICATE" in provider_config.get("certificate", "")
                or len(provider_config.get("certificate", "")) > 100
            ),
        })
        checklist.append({
            "check": "name_id_format",
            "label": "NameID format is specified",
            "passed": bool(provider_config.get("name_id_format")),
        })
        checklist.append({
            "check": "slo_url_optional",
            "label": "Single Logout URL (optional)",
            "passed": True,
            "note": "SLO URL is not set" if not provider_config.get("slo_url") else "SLO URL configured",
        })
    else:
        # OIDC checks
        checklist.append({
            "check": "client_id_present",
            "label": "Client ID is configured",
            "passed": bool(provider_config.get("client_id")),
        })
        checklist.append({
            "check": "client_secret_present",
            "label": "Client Secret is configured",
            "passed": bool(provider_config.get("client_secret")),
        })
        checklist.append({
            "check": "authorization_url_valid",
            "label": "Authorization URL is a valid HTTPS endpoint",
            "passed": (provider_config.get("authorization_url", "")).startswith("https://"),
        })
        checklist.append({
            "check": "token_url_valid",
            "label": "Token URL is a valid HTTPS endpoint",
            "passed": (provider_config.get("token_url", "")).startswith("https://"),
        })
        checklist.append({
            "check": "userinfo_url_valid",
            "label": "UserInfo URL is a valid HTTPS endpoint",
            "passed": (provider_config.get("userinfo_url", "")).startswith("https://"),
        })
        checklist.append({
            "check": "scopes_present",
            "label": "OAuth scopes are configured",
            "passed": bool(provider_config.get("scopes")),
            "note": f"Scopes: {provider_config.get('scopes', 'openid email profile')}",
        })

    # Domain whitelist check
    checklist.append({
        "check": "domain_whitelist",
        "label": "At least one email domain is whitelisted",
        "passed": len(cfg["domain_whitelist"]) > 0,
        "note": f"Domains: {', '.join(cfg['domain_whitelist'])}" if cfg["domain_whitelist"] else "No domains configured",
    })

    passed_count = sum(1 for c in checklist if c["passed"])
    total_count = len(checklist)
    all_passed = passed_count == total_count

    # Update status to testing
    cfg["status"] = SSOStatus.testing.value
    cfg["updated_at"] = datetime.now(timezone.utc).isoformat()

    return {
        "config_id": config_id,
        "provider_type": provider_type,
        "provider_name": cfg["provider_name"],
        "test_result": "PASS" if all_passed else "FAIL",
        "passed": passed_count,
        "total": total_count,
        "checklist": checklist,
        "message": (
            "All checks passed. You can now activate this SSO configuration."
            if all_passed
            else f"{total_count - passed_count} check(s) failed. Review the checklist and update the configuration."
        ),
    }


# ---------------------------------------------------------------------------
# 6. POST "/{config_id}/activate" -- Activate SSO
# ---------------------------------------------------------------------------

@router.post("/{config_id}/activate")
def activate_sso_config(config_id: str, email: str = Depends(verify_token)):
    """Set the SSO configuration status to active.

    It is recommended to run the test endpoint first.
    """
    cfg = _get_config_by_id(config_id)
    if cfg is None:
        raise HTTPException(status_code=404, detail="SSO configuration not found")
    caller_org = _org_id_for_user(email)
    if cfg["org_id"] != caller_org:
        raise HTTPException(status_code=403, detail="Access denied to this SSO configuration")
    if cfg["status"] == SSOStatus.active.value:
        return {"message": "SSO configuration is already active", "id": config_id, "status": "active"}

    cfg["status"] = SSOStatus.active.value
    cfg["updated_at"] = datetime.now(timezone.utc).isoformat()
    logger.info("SSO activated: id=%s org=%s by=%s", config_id, caller_org, email)

    return {
        "message": "SSO configuration activated",
        "id": config_id,
        "status": "active",
        "enforce": cfg["enforce"],
        "domain_whitelist": cfg["domain_whitelist"],
        "warning": (
            "Users with matching email domains will be required to authenticate via SSO."
            if cfg["enforce"]
            else "SSO is available but not enforced. Users can still log in with password."
        ),
    }


# ---------------------------------------------------------------------------
# 7. POST "/{config_id}/deactivate" -- Deactivate SSO
# ---------------------------------------------------------------------------

@router.post("/{config_id}/deactivate")
def deactivate_sso_config(config_id: str, email: str = Depends(verify_token)):
    """Deactivate an SSO configuration.  Users revert to password-based auth."""
    cfg = _get_config_by_id(config_id)
    if cfg is None:
        raise HTTPException(status_code=404, detail="SSO configuration not found")
    caller_org = _org_id_for_user(email)
    if cfg["org_id"] != caller_org:
        raise HTTPException(status_code=403, detail="Access denied to this SSO configuration")

    cfg["status"] = SSOStatus.inactive.value
    cfg["updated_at"] = datetime.now(timezone.utc).isoformat()
    logger.info("SSO deactivated: id=%s org=%s by=%s", config_id, caller_org, email)

    return {"message": "SSO configuration deactivated", "id": config_id, "status": "inactive"}


# ---------------------------------------------------------------------------
# 8. GET "/saml/metadata/{config_id}" -- SP Metadata XML
# ---------------------------------------------------------------------------

@router.get("/saml/metadata/{config_id}", response_class=Response)
def saml_sp_metadata(config_id: str):
    """Return SAML Service Provider metadata XML.

    This XML document can be uploaded directly into your SAML IdP (Okta,
    Azure AD, etc.) to configure the trust relationship.
    """
    cfg = _get_config_by_id(config_id)
    if cfg is None:
        raise HTTPException(status_code=404, detail="SSO configuration not found")
    if cfg["provider_type"] != "saml":
        raise HTTPException(status_code=400, detail="This endpoint is only available for SAML configurations")

    name_id_format = cfg["config"].get(
        "name_id_format",
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    )

    metadata_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="{SP_ENTITY_ID}"
    validUntil="2027-12-31T23:59:59Z">
  <md:SPSSODescriptor
      AuthnRequestsSigned="true"
      WantAssertionsSigned="true"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>{name_id_format}</md:NameIDFormat>
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="{SP_ACS_URL}"
        index="0"
        isDefault="true"/>
    <md:AttributeConsumingService index="0" isDefault="true">
      <md:ServiceName xml:lang="en">GovernLayer</md:ServiceName>
      <md:ServiceDescription xml:lang="en">AI Governance Platform SSO</md:ServiceDescription>
      <md:RequestedAttribute
          FriendlyName="Email"
          Name="urn:oid:0.9.2342.19200300.100.1.3"
          NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
          isRequired="true"/>
      <md:RequestedAttribute
          FriendlyName="DisplayName"
          Name="urn:oid:2.16.840.1.113730.3.1.241"
          NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
          isRequired="false"/>
    </md:AttributeConsumingService>
  </md:SPSSODescriptor>
  <md:Organization>
    <md:OrganizationName xml:lang="en">GovernLayer</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="en">GovernLayer AI Governance</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="en">https://www.governlayer.ai</md:OrganizationURL>
  </md:Organization>
  <md:ContactPerson contactType="technical">
    <md:GivenName>GovernLayer Support</md:GivenName>
    <md:EmailAddress>support@governlayer.ai</md:EmailAddress>
  </md:ContactPerson>
</md:EntityDescriptor>"""

    return Response(
        content=metadata_xml,
        media_type="application/xml",
        headers={"Content-Disposition": f"inline; filename=governlayer-sp-metadata-{config_id}.xml"},
    )


# ---------------------------------------------------------------------------
# 9. POST "/saml/acs" -- SAML Assertion Consumer Service
# ---------------------------------------------------------------------------

@router.post("/saml/acs")
def saml_assertion_consumer_service(payload: SAMLResponsePayload):
    """SAML Assertion Consumer Service (ACS) endpoint.

    The IdP redirects/POSTs the user here after successful authentication.
    We decode the SAMLResponse, extract the NameID (email), and issue a
    GovernLayer JWT.

    TODO (production hardening):
      - Validate the XML signature against the IdP certificate (use xmlsec1
        or python3-saml).
      - Check Conditions/NotBefore/NotOnOrAfter for replay protection.
      - Verify Destination matches our ACS URL.
      - Verify InResponseTo matches a pending AuthnRequest ID.
      - Check Audience restriction.
    """
    # Step 1: Base64-decode the SAML Response
    try:
        saml_xml_bytes = base64.b64decode(payload.SAMLResponse)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid SAMLResponse: not valid base64")

    # Step 2: Parse the XML and extract NameID
    try:
        saml_xml_str = saml_xml_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="Invalid SAMLResponse: unable to decode as UTF-8")

    email = _extract_nameid_from_saml(saml_xml_str)
    if not email or "@" not in email:
        raise HTTPException(
            status_code=400,
            detail="Could not extract a valid email address from the SAML assertion NameID",
        )

    # Step 3: Verify the email domain matches an active SAML SSO config
    domain = email.split("@")[-1].lower()
    matched_config = _find_active_config_for_domain(domain, "saml")
    if matched_config is None:
        logger.warning("SAML ACS: no active SAML config for domain=%s email=%s", domain, email)
        raise HTTPException(
            status_code=403,
            detail=f"No active SSO configuration found for domain '{domain}'",
        )

    # Step 4: Issue a GovernLayer JWT
    token = create_token(email)
    logger.info("SAML SSO login: email=%s domain=%s config=%s", email, domain, matched_config["id"])

    return {
        "access_token": token,
        "token_type": "bearer",
        "email": email,
        "sso_provider": matched_config["provider_name"],
        "sso_config_id": matched_config["id"],
        "auth_method": "saml",
    }


def _extract_nameid_from_saml(xml_str: str) -> str | None:
    """Extract the NameID value from a SAML Response XML.

    Handles namespaced and non-namespaced NameID elements.  This is a
    simplified parser -- production code should use a proper SAML library.
    """
    # SAML 2.0 namespaces
    namespaces = {
        "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
        "saml2": "urn:oasis:names:tc:SAML:2.0:assertion",
        "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    }

    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    # Try standard SAML 2.0 namespace paths
    for ns_prefix in ("saml", "saml2"):
        ns = namespaces[ns_prefix]
        # Path: Response -> Assertion -> Subject -> NameID
        for name_id in root.iter(f"{{{ns}}}NameID"):
            text = (name_id.text or "").strip()
            if text:
                return text

    # Fallback: look for any element named NameID regardless of namespace
    for elem in root.iter():
        local_name = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
        if local_name == "NameID":
            text = (elem.text or "").strip()
            if text:
                return text

    return None


def _find_active_config_for_domain(
    domain: str, provider_type: str
) -> dict[str, Any] | None:
    """Find an active SSO config whose domain_whitelist includes the given domain."""
    for configs in _sso_configs.values():
        for cfg in configs:
            if (
                cfg["status"] == SSOStatus.active.value
                and cfg["provider_type"] == provider_type
                and domain in cfg["domain_whitelist"]
            ):
                return cfg
    return None


# ---------------------------------------------------------------------------
# 10. GET "/oidc/authorize/{config_id}" -- Redirect to IdP
# ---------------------------------------------------------------------------

@router.get("/oidc/authorize/{config_id}")
def oidc_authorize(config_id: str):
    """Initiate an OIDC authorization code flow.

    Redirects the user to the IdP's authorization endpoint with the
    appropriate query parameters.
    """
    cfg = _get_config_by_id(config_id)
    if cfg is None:
        raise HTTPException(status_code=404, detail="SSO configuration not found")
    if cfg["provider_type"] != "oidc":
        raise HTTPException(status_code=400, detail="This endpoint is only available for OIDC configurations")
    if cfg["status"] != SSOStatus.active.value:
        raise HTTPException(status_code=409, detail="SSO configuration is not active")

    provider_config = cfg["config"]
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    scopes = provider_config.get("scopes", "openid email profile")

    # Store state for validation in the callback
    _oidc_pending_states[state] = {
        "config_id": config_id,
        "nonce": nonce,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    params = {
        "response_type": "code",
        "client_id": provider_config["client_id"],
        "redirect_uri": SP_OIDC_CALLBACK_URL,
        "scope": scopes,
        "state": state,
        "nonce": nonce,
    }

    authorization_url = provider_config["authorization_url"]
    redirect_url = f"{authorization_url}?{urllib.parse.urlencode(params)}"

    logger.info("OIDC authorize redirect: config=%s url=%s", config_id, authorization_url)

    return RedirectResponse(url=redirect_url, status_code=302)


# ---------------------------------------------------------------------------
# 11. GET "/oidc/callback" -- OIDC callback
# ---------------------------------------------------------------------------

@router.get("/oidc/callback")
def oidc_callback(
    code: str = Query(..., description="Authorization code from the IdP"),
    state: str = Query(..., description="State parameter for CSRF protection"),
    error: str | None = Query(default=None, description="Error code if the IdP returned an error"),
    error_description: str | None = Query(default=None),
):
    """OIDC authorization code callback.

    In production, this endpoint exchanges the authorization code for tokens
    by calling the IdP's token endpoint.  Here we simulate the token exchange
    and extract the user's email from the state/code context.

    TODO (production hardening):
      - Perform an actual HTTP POST to the IdP's token_url with the code.
      - Validate the id_token signature (JWK verification).
      - Call the userinfo_url to retrieve user attributes.
      - Verify the nonce matches the one sent in the authorize request.
    """
    if error:
        raise HTTPException(
            status_code=400,
            detail=f"IdP returned an error: {error} - {error_description or 'no details'}",
        )

    # Validate state
    pending = _oidc_pending_states.pop(state, None)
    if pending is None:
        raise HTTPException(status_code=400, detail="Invalid or expired state parameter (possible CSRF)")

    config_id = pending["config_id"]
    cfg = _get_config_by_id(config_id)
    if cfg is None:
        raise HTTPException(status_code=404, detail="SSO configuration no longer exists")

    # --- Simulated token exchange ---
    # In production: POST to cfg["config"]["token_url"] with grant_type=authorization_code,
    # code=code, redirect_uri=SP_OIDC_CALLBACK_URL, client_id, client_secret.
    # Then decode the id_token JWT to get the user's email.
    #
    # For this implementation, we derive a deterministic email from the code
    # to allow end-to-end testing without a real IdP.  Real implementations
    # would never do this.
    simulated_email = _simulate_oidc_token_exchange(code, cfg)

    if not simulated_email or "@" not in simulated_email:
        raise HTTPException(
            status_code=502,
            detail="Failed to retrieve user email from IdP token exchange",
        )

    # Verify domain
    domain = simulated_email.split("@")[-1].lower()
    if cfg["domain_whitelist"] and domain not in cfg["domain_whitelist"]:
        raise HTTPException(
            status_code=403,
            detail=f"Email domain '{domain}' is not in the allowed domain list for this SSO configuration",
        )

    # Issue JWT
    token = create_token(simulated_email)
    logger.info("OIDC SSO login: email=%s config=%s", simulated_email, config_id)

    return {
        "access_token": token,
        "token_type": "bearer",
        "email": simulated_email,
        "sso_provider": cfg["provider_name"],
        "sso_config_id": config_id,
        "auth_method": "oidc",
    }


def _simulate_oidc_token_exchange(code: str, cfg: dict[str, Any]) -> str | None:
    """Simulate an OIDC token exchange.

    In production this would be an HTTP POST to the IdP token endpoint:
        POST {token_url}
        Content-Type: application/x-www-form-urlencoded

        grant_type=authorization_code
        &code={code}
        &redirect_uri={SP_OIDC_CALLBACK_URL}
        &client_id={client_id}
        &client_secret={client_secret}

    The response would contain an id_token (JWT) whose payload includes the
    user's email.  We simulate this by returning a placeholder email from
    the first whitelisted domain, or decoding the code if it looks like a
    base64-encoded email.
    """
    # Try to decode the code as a base64-encoded email (useful for testing)
    try:
        decoded = base64.b64decode(code).decode("utf-8")
        if "@" in decoded:
            return decoded.strip()
    except Exception:
        pass

    # Fallback: generate a simulated user email using the first whitelisted domain
    domains = cfg.get("domain_whitelist", [])
    if domains:
        return f"sso-user@{domains[0]}"

    return None


# ---------------------------------------------------------------------------
# 12. GET "/providers" -- Supported IdP providers with setup instructions
# ---------------------------------------------------------------------------

@router.get("/providers")
def list_supported_providers():
    """List supported SSO identity providers with setup instructions."""
    return {
        "providers": [
            {
                "name": "Okta",
                "type": "saml",
                "logo_url": "https://www.okta.com/sites/default/files/Okta_Logo_BrightBlue_Medium.png",
                "setup_steps": [
                    "Log in to your Okta admin console.",
                    "Go to Applications > Create App Integration.",
                    "Select 'SAML 2.0' and click Next.",
                    "Set the Single sign-on URL to: https://api.governlayer.ai/v1/sso/saml/acs",
                    "Set the Audience URI (SP Entity ID) to: https://api.governlayer.ai/v1/sso",
                    "Set Name ID format to 'EmailAddress'.",
                    "Under Attribute Statements, map 'email' to 'user.email'.",
                    "Complete the wizard and download the IdP metadata or copy the SSO URL, Entity ID, and certificate.",
                    "Use POST /v1/sso/configure with the SAML details from Okta.",
                    "Download the SP metadata from GET /v1/sso/saml/metadata/{config_id} if your Okta setup requires it.",
                ],
                "docs_url": "https://developer.okta.com/docs/guides/build-sso-integration/saml2/main/",
            },
            {
                "name": "Azure AD",
                "type": "saml",
                "logo_url": "https://learn.microsoft.com/en-us/entra/identity/saas-apps/media/tutorial-list/active-directory-saas-app-tutorial.png",
                "setup_steps": [
                    "Go to Azure Portal > Microsoft Entra ID > Enterprise Applications.",
                    "Click 'New application' > 'Create your own application'.",
                    "Select 'Integrate any other application you don't find in the gallery (Non-gallery)'.",
                    "Under 'Single sign-on', select 'SAML'.",
                    "In 'Basic SAML Configuration', set Identifier (Entity ID) to: https://api.governlayer.ai/v1/sso",
                    "Set Reply URL (ACS) to: https://api.governlayer.ai/v1/sso/saml/acs",
                    "Download the Federation Metadata XML or copy the Login URL, Identifier, and Certificate.",
                    "Use POST /v1/sso/configure with the SAML details from Azure AD.",
                    "Assign users/groups to the application in Azure AD.",
                ],
                "docs_url": "https://learn.microsoft.com/en-us/entra/identity/saas-apps/saml-tutorial",
            },
            {
                "name": "Google Workspace",
                "type": "saml",
                "logo_url": "https://workspace.google.com/static/img/logo-realtime-collaboration.svg",
                "setup_steps": [
                    "Go to Google Admin Console > Apps > Web and mobile apps.",
                    "Click 'Add app' > 'Add custom SAML app'.",
                    "Download the IdP metadata (Google Identity Provider details).",
                    "Set ACS URL to: https://api.governlayer.ai/v1/sso/saml/acs",
                    "Set Entity ID to: https://api.governlayer.ai/v1/sso",
                    "Set Name ID format to 'EMAIL' and Name ID to 'Basic Information > Primary email'.",
                    "Add attribute mappings: 'email' -> 'Basic Information > Primary email'.",
                    "Use POST /v1/sso/configure with the SAML details from Google.",
                    "Turn on the app for the relevant organizational units.",
                ],
                "docs_url": "https://support.google.com/a/answer/6087519",
            },
            {
                "name": "OneLogin",
                "type": "saml",
                "logo_url": "https://www.onelogin.com/hubfs/brand-assets/onelogin-logo.svg",
                "setup_steps": [
                    "Go to OneLogin Admin > Applications > Add App.",
                    "Search for 'SAML Custom Connector (Advanced)' and select it.",
                    "Under 'Configuration', set ACS URL to: https://api.governlayer.ai/v1/sso/saml/acs",
                    "Set Audience (EntityID) to: https://api.governlayer.ai/v1/sso",
                    "Under 'SSO', copy the SAML 2.0 Endpoint (HTTP), Issuer URL, and X.509 Certificate.",
                    "Use POST /v1/sso/configure with the SAML details from OneLogin.",
                    "Assign users to the application in OneLogin.",
                ],
                "docs_url": "https://developers.onelogin.com/saml",
            },
            {
                "name": "JumpCloud",
                "type": "saml",
                "logo_url": "https://jumpcloud.com/wp-content/uploads/2023/01/JC-Logo-Mark-Color.svg",
                "setup_steps": [
                    "Go to JumpCloud Admin Console > SSO Applications.",
                    "Click '+ Add New Application' and select 'Custom SAML App'.",
                    "Set SP Entity ID to: https://api.governlayer.ai/v1/sso",
                    "Set ACS URL to: https://api.governlayer.ai/v1/sso/saml/acs",
                    "Set SAMLSubject NameID to 'email'.",
                    "Set SAMLSubject NameID Format to 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'.",
                    "Download the certificate and copy the IdP URL.",
                    "Use POST /v1/sso/configure with the SAML details from JumpCloud.",
                    "Activate the application and bind users/groups.",
                ],
                "docs_url": "https://jumpcloud.com/support/sso-with-saml-2-0",
            },
            {
                "name": "Okta (OIDC)",
                "type": "oidc",
                "logo_url": "https://www.okta.com/sites/default/files/Okta_Logo_BrightBlue_Medium.png",
                "setup_steps": [
                    "Log in to your Okta admin console.",
                    "Go to Applications > Create App Integration.",
                    "Select 'OIDC - OpenID Connect' and 'Web Application', then click Next.",
                    "Set the Sign-in redirect URI to: https://api.governlayer.ai/v1/sso/oidc/callback",
                    "Note the Client ID and Client Secret from the application settings.",
                    "Find your Okta domain's OIDC endpoints at: https://{your-okta-domain}/.well-known/openid-configuration",
                    "Use POST /v1/sso/configure with provider_type='oidc' and the OIDC details.",
                ],
                "docs_url": "https://developer.okta.com/docs/guides/implement-grant-type/authcode/main/",
            },
            {
                "name": "Azure AD (OIDC)",
                "type": "oidc",
                "logo_url": "https://learn.microsoft.com/en-us/entra/identity/saas-apps/media/tutorial-list/active-directory-saas-app-tutorial.png",
                "setup_steps": [
                    "Go to Azure Portal > Microsoft Entra ID > App registrations > New registration.",
                    "Set the Redirect URI to: https://api.governlayer.ai/v1/sso/oidc/callback (Web platform).",
                    "Note the Application (client) ID and Directory (tenant) ID.",
                    "Under 'Certificates & secrets', create a new Client Secret.",
                    "OIDC endpoints are at: https://login.microsoftonline.com/{tenant-id}/v2.0/.well-known/openid-configuration",
                    "Use POST /v1/sso/configure with provider_type='oidc' and the OIDC details.",
                ],
                "docs_url": "https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc",
            },
        ],
    }
