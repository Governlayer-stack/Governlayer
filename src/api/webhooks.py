"""Webhook dispatcher — notify enterprise systems of governance events.

Design:

  * dispatch_event() records a WebhookDelivery row (status="queued") then
    spawns a daemon thread to deliver it. The thread updates the row on
    completion. If the app dies mid-flight the row stays "queued" and a
    background sweeper picks it up.

  * Retry policy: exponential backoff at attempts 2 and 3, then terminal
    failure. Retries are handled by the sweeper.

  * SSRF protection: URLs pointing at private/internal networks are
    rejected before any delivery attempt is made.

  * Observability: /webhooks/deliveries lists recent deliveries. The
    /webhooks/deliveries/{id}/retry endpoint lets an operator re-fire a
    failed delivery on demand.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import socket
import time
from datetime import datetime, timedelta
from threading import Thread
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from src.models.database import SessionLocal, get_db
from src.security.api_key_auth import AuthContext, require_scope

logger = logging.getLogger("governlayer.webhooks")

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


# ---------------------------------------------------------------------------
# SSRF hardening
# ---------------------------------------------------------------------------

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # cloud metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_safe_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ("https",):
        return False
    hostname = parsed.hostname
    if not hostname:
        return False
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


# ---------------------------------------------------------------------------
# Retry policy
# ---------------------------------------------------------------------------

MAX_ATTEMPTS = 3
_BACKOFF_SECONDS = {1: 0, 2: 60, 3: 900}  # attempt 2 waits 1 min, attempt 3 waits 15 min


def _backoff_for(attempt: int) -> int:
    return _BACKOFF_SECONDS.get(attempt, 3600)


# ---------------------------------------------------------------------------
# Public API — used by every /credit, /fraud, /govern, /agents endpoint
# ---------------------------------------------------------------------------


def dispatch_event(event_type: str, payload: dict, org_id: int | None, db: Session):
    """Fire webhooks for the given event.

    Writes a WebhookDelivery row per matching hook then spawns a daemon
    thread to attempt delivery. Threads update the row on completion.
    """
    if not org_id:
        return

    from src.models.tenant import Webhook
    from src.models.webhooks import WebhookDelivery

    hooks = (
        db.query(Webhook)
        .filter(Webhook.org_id == org_id, Webhook.is_active.is_(True))
        .all()
    )

    for hook in hooks:
        events = [e.strip() for e in hook.events.split(",")]
        if event_type not in events and "*" not in events:
            continue

        if not _is_safe_url(hook.url):
            logger.warning("Blocked webhook to unsafe URL: %s (org=%s)", hook.url, org_id)
            continue

        # Record the delivery attempt
        preview = json.dumps({"event": event_type, "data": payload}, default=str)[:1024]
        delivery = WebhookDelivery(
            webhook_id=hook.id,
            org_id=org_id,
            event_type=event_type,
            target_url=hook.url,
            payload_preview=preview,
            attempt=1,
            status="queued",
            next_retry_at=None,
        )
        db.add(delivery)
        db.flush()
        delivery_id = delivery.id

        # Spawn the send. We commit before returning so the delivery row is
        # visible even if the thread finishes first.
        Thread(
            target=_send_and_record,
            args=(delivery_id, hook.url, hook.secret, event_type, payload),
            daemon=True,
        ).start()


# ---------------------------------------------------------------------------
# Delivery worker (runs in a background thread)
# ---------------------------------------------------------------------------


def _send_and_record(delivery_id: int, url: str, secret: str, event_type: str, payload: dict) -> None:
    """Attempt a single delivery and update the WebhookDelivery row."""
    from src.models.webhooks import WebhookDelivery

    db = SessionLocal()
    try:
        delivery = db.query(WebhookDelivery).filter(WebhookDelivery.id == delivery_id).first()
        if delivery is None:
            return

        started = time.perf_counter()
        body = json.dumps({"event": event_type, "data": payload}, default=str).encode()
        signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

        try:
            req = Request(url, data=body, method="POST", headers={
                "Content-Type": "application/json",
                "X-GovernLayer-Event": event_type,
                "X-GovernLayer-Signature": f"sha256={signature}",
                "X-GovernLayer-Attempt": str(delivery.attempt),
                "X-GovernLayer-Delivery-Id": str(delivery_id),
            })
            resp = urlopen(req, timeout=10)
            latency = round((time.perf_counter() - started) * 1000, 2)
            body_preview = resp.read(1024).decode(errors="replace") if resp else ""
            delivery.status = "delivered"
            delivery.response_status_code = resp.status
            delivery.response_body_preview = body_preview
            delivery.latency_ms = latency
            delivery.completed_at = datetime.utcnow()
            logger.info("Webhook delivered: %s -> %s (attempt=%s)", event_type, url, delivery.attempt)
        except HTTPError as http_err:
            latency = round((time.perf_counter() - started) * 1000, 2)
            body_preview = ""
            try:
                body_preview = http_err.read(1024).decode(errors="replace")
            except Exception:  # noqa: BLE001
                pass
            delivery.response_status_code = http_err.code
            delivery.response_body_preview = body_preview
            delivery.latency_ms = latency
            delivery.error = f"HTTP {http_err.code}"
            _mark_retry_or_terminal(delivery)
            logger.warning("Webhook HTTP %s: %s -> %s (attempt=%s)", http_err.code, event_type, url, delivery.attempt)
        except (URLError, socket.timeout, OSError) as exc:
            delivery.latency_ms = round((time.perf_counter() - started) * 1000, 2)
            delivery.error = str(exc)[:500]
            _mark_retry_or_terminal(delivery)
            logger.warning("Webhook error: %s -> %s: %s (attempt=%s)", event_type, url, exc, delivery.attempt)
        except Exception as exc:  # noqa: BLE001
            delivery.error = f"unexpected: {exc}"[:500]
            _mark_retry_or_terminal(delivery)
            logger.error("Webhook unexpected error: %s", exc)

        db.commit()
    finally:
        db.close()


def _mark_retry_or_terminal(delivery) -> None:
    """Decide whether the delivery gets another attempt or is terminal."""
    if delivery.attempt >= MAX_ATTEMPTS:
        delivery.status = "failed_terminal"
        delivery.completed_at = datetime.utcnow()
    else:
        delivery.status = "failed_retryable"
        delivery.next_retry_at = datetime.utcnow() + timedelta(
            seconds=_backoff_for(delivery.attempt + 1)
        )


# ---------------------------------------------------------------------------
# Sweeper — retries any delivery whose next_retry_at has passed.
# Called by src/scheduler.py on a fixed interval.
# ---------------------------------------------------------------------------


def sweep_pending_retries(batch: int = 50) -> int:
    """Process due retries; return the number retried."""
    from src.models.webhooks import WebhookDelivery
    from src.models.tenant import Webhook

    db = SessionLocal()
    try:
        now = datetime.utcnow()
        rows = (
            db.query(WebhookDelivery)
            .filter(
                WebhookDelivery.status == "failed_retryable",
                WebhookDelivery.next_retry_at <= now,
            )
            .limit(batch)
            .all()
        )
        count = 0
        for row in rows:
            hook = db.query(Webhook).filter(Webhook.id == row.webhook_id).first()
            if hook is None or not hook.is_active:
                row.status = "failed_terminal"
                row.completed_at = now
                continue
            # Bump attempt and re-fire in a new thread
            row.attempt += 1
            row.status = "queued"
            row.next_retry_at = None
            try:
                payload = json.loads(row.payload_preview).get("data", {})
            except Exception:  # noqa: BLE001
                payload = {"_note": "payload unavailable on retry"}
            db.commit()
            Thread(
                target=_send_and_record,
                args=(row.id, hook.url, hook.secret, row.event_type, payload),
                daemon=True,
            ).start()
            count += 1
        return count
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Operator endpoints — observability + manual retry
# ---------------------------------------------------------------------------


@router.get("/deliveries")
def list_deliveries(
    status: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = 100,
    auth: AuthContext = Depends(require_scope("audit")),
    db: Session = Depends(get_db),
):
    """List recent webhook deliveries (filter by status or event type)."""
    from src.models.webhooks import WebhookDelivery
    q = db.query(WebhookDelivery)
    if auth.org_id:
        q = q.filter(WebhookDelivery.org_id == auth.org_id)
    if status:
        q = q.filter(WebhookDelivery.status == status)
    if event_type:
        q = q.filter(WebhookDelivery.event_type == event_type)
    rows = q.order_by(WebhookDelivery.created_at.desc()).limit(max(1, min(500, limit))).all()
    return {
        "count": len(rows),
        "deliveries": [
            {
                "id": r.id,
                "event_type": r.event_type,
                "target_url": r.target_url,
                "status": r.status,
                "attempt": r.attempt,
                "response_status_code": r.response_status_code,
                "latency_ms": r.latency_ms,
                "error": r.error,
                "next_retry_at": r.next_retry_at.isoformat() if r.next_retry_at else None,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            }
            for r in rows
        ],
    }


@router.post("/deliveries/{delivery_id}/retry")
def retry_delivery(
    delivery_id: int,
    auth: AuthContext = Depends(require_scope("audit")),
    db: Session = Depends(get_db),
):
    """Force a retry of a specific failed delivery."""
    from src.models.tenant import Webhook
    from src.models.webhooks import WebhookDelivery

    row = db.query(WebhookDelivery).filter(WebhookDelivery.id == delivery_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="delivery not found")
    if auth.org_id and row.org_id != auth.org_id:
        raise HTTPException(status_code=404, detail="delivery not found")
    if row.status == "delivered":
        raise HTTPException(status_code=409, detail="delivery already succeeded")

    hook = db.query(Webhook).filter(Webhook.id == row.webhook_id).first()
    if not hook or not hook.is_active:
        raise HTTPException(status_code=410, detail="webhook target no longer active")

    row.attempt += 1
    row.status = "queued"
    row.next_retry_at = None
    row.error = None
    db.commit()

    try:
        payload = json.loads(row.payload_preview).get("data", {})
    except Exception:  # noqa: BLE001
        payload = {"_note": "payload unavailable on manual retry"}

    Thread(
        target=_send_and_record,
        args=(row.id, hook.url, hook.secret, row.event_type, payload),
        daemon=True,
    ).start()

    return {"delivery_id": row.id, "status": "queued", "attempt": row.attempt}


@router.get("/deliveries/stats")
def deliveries_stats(
    auth: AuthContext = Depends(require_scope("audit")),
    db: Session = Depends(get_db),
):
    """Count deliveries by status for the last 24h."""
    from sqlalchemy import func
    from src.models.webhooks import WebhookDelivery

    since = datetime.utcnow() - timedelta(hours=24)
    q = (
        db.query(WebhookDelivery.status, func.count(WebhookDelivery.id))
        .filter(WebhookDelivery.created_at >= since)
    )
    if auth.org_id:
        q = q.filter(WebhookDelivery.org_id == auth.org_id)
    rows = q.group_by(WebhookDelivery.status).all()
    counts = {s: c for s, c in rows}
    total = sum(counts.values())
    delivered = counts.get("delivered", 0)
    return {
        "window_hours": 24,
        "total": total,
        "by_status": counts,
        "success_rate": round(delivered / total, 4) if total else None,
    }
