"""Webhook dispatcher — notify enterprise systems of governance events."""

import hashlib
import hmac
import json
import logging
from threading import Thread
from urllib.error import URLError
from urllib.request import Request, urlopen

from sqlalchemy.orm import Session

logger = logging.getLogger("governlayer.webhooks")


def dispatch_event(event_type: str, payload: dict, org_id: int | None, db: Session):
    """Fire webhooks for the given event, non-blocking."""
    if not org_id:
        return

    from src.models.tenant import Webhook
    hooks = db.query(Webhook).filter(
        Webhook.org_id == org_id,
        Webhook.is_active.is_(True),
    ).all()

    for hook in hooks:
        events = [e.strip() for e in hook.events.split(",")]
        if event_type in events or "*" in events:
            Thread(target=_send_webhook, args=(hook.url, hook.secret, event_type, payload), daemon=True).start()


def _send_webhook(url: str, secret: str, event_type: str, payload: dict):
    """Send a single webhook with HMAC-SHA256 signature."""
    try:
        body = json.dumps({"event": event_type, "data": payload}, default=str).encode()
        signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

        req = Request(url, data=body, method="POST", headers={
            "Content-Type": "application/json",
            "X-GovernLayer-Event": event_type,
            "X-GovernLayer-Signature": f"sha256={signature}",
        })
        urlopen(req, timeout=10)
        logger.info(f"Webhook delivered: {event_type} -> {url}")
    except URLError as e:
        logger.warning(f"Webhook failed: {event_type} -> {url}: {e}")
    except Exception as e:
        logger.error(f"Webhook error: {event_type} -> {url}: {e}")
