"""Email notification service — Resend (primary), SMTP (fallback), log (dev)."""

import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional

logger = logging.getLogger("governlayer.email")


def send_email(to: str, subject: str, html_body: str, text_body: Optional[str] = None) -> bool:
    """Send email via configured provider. Returns True on success."""
    from src.config import get_settings
    settings = get_settings()

    # Try Resend first
    if settings.resend_api_key:
        return _send_resend(to, subject, html_body, settings)

    # Try SMTP fallback
    if settings.smtp_host:
        return _send_smtp(to, subject, html_body, text_body, settings)

    # Dev mode: log the email
    logger.info("EMAIL [dev mode] To: %s | Subject: %s", to, subject)
    logger.debug("EMAIL body: %s", text_body or html_body[:500])
    return True


def _send_resend(to, subject, html_body, settings) -> bool:
    try:
        import httpx
        resp = httpx.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {settings.resend_api_key}",
                "User-Agent": "GovernLayer/1.0 (https://governlayer.ai)",
            },
            json={
                "from": settings.email_from,
                "to": [to],
                "subject": subject,
                "html": html_body,
            },
            timeout=10,
        )
        if resp.status_code in (200, 201):
            logger.info("Email sent via Resend to %s", to)
            return True
        logger.warning("Resend failed: %s %s", resp.status_code, resp.text[:200])
        return False
    except Exception as e:
        logger.error("Resend error: %s", e)
        return False


def _send_smtp(to, subject, html_body, text_body, settings) -> bool:
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = settings.email_from
        msg["To"] = to
        if text_body:
            msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as server:
            if settings.smtp_use_tls:
                server.starttls()
            if settings.smtp_user and settings.smtp_password:
                server.login(settings.smtp_user, settings.smtp_password)
            server.sendmail(settings.email_from, [to], msg.as_string())
        logger.info("Email sent via SMTP to %s", to)
        return True
    except Exception as e:
        logger.error("SMTP error: %s", e)
        return False
