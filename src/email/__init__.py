"""GovernLayer transactional email system — Resend provider with graceful fallback."""

from src.email.service import (
    send_api_key_created,
    send_billing_receipt,
    send_email,
    send_escalation_alert,
    send_password_reset,
    send_welcome_email,
)

__all__ = [
    "send_email",
    "send_welcome_email",
    "send_password_reset",
    "send_api_key_created",
    "send_escalation_alert",
    "send_billing_receipt",
]
