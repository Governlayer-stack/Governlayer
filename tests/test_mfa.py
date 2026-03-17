"""Tests for TOTP Multi-Factor Authentication."""

import pyotp


def test_mfa_status_disabled_by_default(client, auth_headers):
    r = client.get("/auth/mfa/status", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["mfa_enabled"] is False


def test_mfa_setup_returns_secret_and_qr(client, auth_headers):
    r = client.post("/auth/mfa/setup", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "secret" in data
    assert "provisioning_uri" in data
    assert "qr_code_base64" in data
    assert "backup_codes" in data
    assert len(data["backup_codes"]) == 10
    assert "GovernLayer" in data["provisioning_uri"]


def test_mfa_full_lifecycle(client, auth_headers):
    """Setup -> verify -> enable -> status -> disable."""
    # Setup
    setup = client.post("/auth/mfa/setup", headers=auth_headers).json()
    secret = setup["secret"]

    # Generate valid TOTP code
    totp = pyotp.TOTP(secret)
    code = totp.now()

    # Verify and enable
    r = client.post("/auth/mfa/verify", json={"code": code}, headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["mfa_enabled"] is True

    # Status should show enabled
    r = client.get("/auth/mfa/status", headers=auth_headers)
    assert r.json()["mfa_enabled"] is True

    # Disable with TOTP code
    code = totp.now()
    r = client.post("/auth/mfa/disable", json={"code": code}, headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["mfa_enabled"] is False


def test_mfa_verify_invalid_code(client, auth_headers):
    client.post("/auth/mfa/setup", headers=auth_headers)
    r = client.post("/auth/mfa/verify", json={"code": "000000"}, headers=auth_headers)
    assert r.status_code == 400


def test_mfa_setup_already_enabled(client, auth_headers):
    """Can't setup MFA if already enabled."""
    setup = client.post("/auth/mfa/setup", headers=auth_headers).json()
    totp = pyotp.TOTP(setup["secret"])
    client.post("/auth/mfa/verify", json={"code": totp.now()}, headers=auth_headers)

    r = client.post("/auth/mfa/setup", headers=auth_headers)
    assert r.status_code == 400


def test_mfa_disable_with_backup_code(client, auth_headers):
    """Can disable MFA using a backup code."""
    setup = client.post("/auth/mfa/setup", headers=auth_headers).json()
    totp = pyotp.TOTP(setup["secret"])
    client.post("/auth/mfa/verify", json={"code": totp.now()}, headers=auth_headers)

    # Use a backup code to disable
    backup = setup["backup_codes"][0]
    r = client.post("/auth/mfa/disable", json={"code": backup}, headers=auth_headers)
    assert r.status_code == 200
