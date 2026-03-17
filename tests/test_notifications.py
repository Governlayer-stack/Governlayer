"""Tests for email notification service."""

from unittest.mock import patch


def test_send_email_dev_mode():
    """Without email provider configured, emails are logged (dev mode)."""
    from src.notifications.email import send_email
    result = send_email("test@example.com", "Test Subject", "<p>Hello</p>")
    assert result is True


def test_password_reset_template():
    from src.notifications.templates import password_reset_email
    subject, html = password_reset_email("abc123token", "user@test.com")
    assert "Password Reset" in subject
    assert "abc123token" in html
    assert "user@test.com" in html
    assert "GovernLayer" in html


def test_incident_alert_template():
    from src.notifications.templates import incident_alert_email
    subject, html = incident_alert_email("Bias detected", "critical", 42)
    assert "CRITICAL" in subject
    assert "Bias detected" in subject
    assert "#42" in html


def test_welcome_template():
    from src.notifications.templates import welcome_email
    subject, html = welcome_email("dev@company.com", "Acme Corp")
    assert "Acme Corp" in subject
    assert "dev@company.com" in html
    assert "Quick start" in html


def test_webhook_failure_template():
    from src.notifications.templates import webhook_failure_email
    subject, html = webhook_failure_email("https://hooks.example.com/gl", "governance.approve", 503)
    assert "Failed" in subject
    assert "503" in html
    assert "hooks.example.com" in html
