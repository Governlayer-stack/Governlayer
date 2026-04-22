"""Webhook dispatcher — notify enterprise systems of governance events."""

import hashlib
import hmac
import ipaddress
import json
import logging
import socket
from threading import Thread
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from sqlalchemy.orm import Session

logger = logging.getLogger("governlayer.webhooks")

# Private/internal IP ranges that webhooks must not target (SSRF prevention)
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / cloud metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_safe_url(url: str) -> bool:
    """Validate webhook URL is not targeting internal/private infrastructure."""
    parsed = urlparse(url)
    if parsed.scheme not in ("https",):
        return False
    hostname = parsed.hostname
    if not hostname:
        return False
    # Block common internal hostnames
    if hostname in ("localhost", "metadata.google.internal", "metadata"):
        return False
    try:
        resolved = socket.getaddrinfo(hostname, parsed.port or 443)
        for _, _, _, _, addr in resolved:
            ip = ipaddress.ip_address(addr[0])
            for net in _BLOCKED_NETWORKS:
                if ip in net:
                    return False
    except socket.gaierror:
        return False
    return True


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
            if not _is_safe_url(hook.url):
                logger.warning("Blocked webhook to unsafe URL: %s (org=%s)", hook.url, org_id)
                continue
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
        logger.info("Webhook delivered: %s -> %s", event_type, url)
    except URLError as e:
        logger.warning("Webhook failed: %s -> %s: %s", event_type, url, e)
    except Exception as e:
        logger.error("Webhook error: %s -> %s: %s", event_type, url, e)
