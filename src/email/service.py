"""GovernLayer transactional email service.

Uses Resend (https://resend.com) as the email provider via httpx.
Falls back to logging when RESEND_API_KEY is not configured (dev/test mode).
"""

import logging
from typing import Optional

from src.email import templates

logger = logging.getLogger("governlayer.email")

_RESEND_ENDPOINT = "https://api.resend.com/emails"
_FROM_ADDRESS = "notifications@governlayer.ai"


# ---------------------------------------------------------------------------
# Core send function
# ---------------------------------------------------------------------------

def send_email(to: str, subject: str, html_body: str, from_addr: Optional[str] = None,
               reply_to: Optional[str] = None) -> bool:
    """Send a transactional email via Resend.

    If RESEND_API_KEY is not configured, logs the email instead of sending.

    Args:
        to: Recipient email address.
        subject: Email subject line.
        html_body: HTML content of the email.
        from_addr: Override the default from address.
        reply_to: Reply-to address (defaults to founders@governlayer.ai).

    Returns:
        True if the email was sent (or logged) successfully.
    """
    from src.config import get_settings
    settings = get_settings()

    api_key = settings.resend_api_key
    sender = from_addr or getattr(settings, "email_from", None) or _FROM_ADDRESS

    if not api_key:
        logger.info(
            "EMAIL [dev mode — no RESEND_API_KEY] To: %s | Subject: %s",
            to,
            subject,
        )
        logger.debug("EMAIL body preview: %.500s", html_body)
        return True

    try:
        import httpx
        payload = {
            "from": sender,
            "to": [to],
            "subject": subject,
            "html": html_body,
            "reply_to": reply_to or "founders@governlayer.ai",
        }
        resp = httpx.post(
            _RESEND_ENDPOINT,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=10,
        )
        if resp.status_code in (200, 201):
            logger.info("Email sent via Resend to %s (subject: %s)", to, subject)
            return True
        logger.error("Resend HTTP error %d: %s", resp.status_code, resp.text[:200])
        return False
    except Exception as exc:
        logger.error("Resend request failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Convenience senders
# ---------------------------------------------------------------------------

def send_welcome_email(email: str, name: str) -> bool:
    """Send welcome email on signup.

    Args:
        email: New user's email address.
        name: Company or user display name.
    """
    subject, html = templates.welcome(email, name)
    return send_email(email, subject, html)


def send_verification_email(email: str, verification_token: str) -> bool:
    """Send email verification link.

    Args:
        email: User's email address.
        verification_token: The secure verification token.
    """
    subject = "Verify your GovernLayer email"
    verify_url = f"https://www.governlayer.ai/verify-email?token={verification_token}"
    html = (
        '<div style="font-family:Inter,sans-serif;max-width:600px;margin:0 auto;background:#0a0e1a;color:#f1f5f9;padding:40px;border-radius:16px">'
        '<h2 style="color:#00d4aa">Verify Your Email</h2>'
        f'<p>Click below to verify your email address:</p>'
        f'<a href="{verify_url}" style="display:inline-block;padding:12px 24px;background:#3b82f6;color:#fff;border-radius:8px;text-decoration:none;font-weight:600;margin:16px 0">Verify Email</a>'
        f'<p style="color:#94a3b8;font-size:13px">Or copy this link: {verify_url}</p>'
        '<p style="color:#64748b;font-size:12px;margin-top:32px">If you didn\'t create this account, ignore this email.</p>'
        '</div>'
    )
    return send_email(email, subject, html)


def send_password_reset(email: str, reset_token: str) -> bool:
    """Send password reset link.

    Args:
        email: User's email address.
        reset_token: The secure reset token.
    """
    subject, html = templates.password_reset(email, reset_token)
    return send_email(email, subject, html)


def send_api_key_created(email: str, key_prefix: str) -> bool:
    """Notify user that a new API key was provisioned.

    Args:
        email: Account owner's email address.
        key_prefix: First characters of the key (e.g. 'gl_abc12').
    """
    subject, html = templates.api_key_created(email, key_prefix)
    return send_email(email, subject, html)


def send_escalation_alert(
    email: str,
    decision_id: str,
    violation_type: str,
    sla_deadline: str,
) -> bool:
    """Notify a reviewer that a governance decision needs human review.

    Args:
        email: Reviewer's email address.
        decision_id: The governance decision identifier.
        violation_type: Type of violation (BLOCKING, CRITICAL, WARNING).
        sla_deadline: ISO-8601 deadline for the review.
    """
    subject, html = templates.escalation_alert(email, decision_id, violation_type, sla_deadline)
    return send_email(email, subject, html)


def send_billing_receipt(email: str, amount: str, plan: str) -> bool:
    """Send payment confirmation receipt.

    Args:
        email: Customer's email address.
        amount: Formatted amount string (e.g. '$49.00').
        plan: Plan name (e.g. 'starter', 'pro', 'enterprise').
    """
    subject, html = templates.billing_receipt(email, amount, plan)
    return send_email(email, subject, html)
