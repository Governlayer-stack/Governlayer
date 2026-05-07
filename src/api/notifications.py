"""
In-app notification center for GovernLayer.

Provides CRUD endpoints for user notifications and a helper function
`send_notification()` that other modules can import to push notifications
into the in-app store.
"""

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from src.security.auth import verify_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/notifications", tags=["Notifications"])

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class NotificationType(str, Enum):
    control_failure = "control_failure"
    evidence_collected = "evidence_collected"
    task_assigned = "task_assigned"
    task_overdue = "task_overdue"
    digest = "digest"
    team_invite = "team_invite"
    scan_complete = "scan_complete"
    policy_violation = "policy_violation"


class Severity(str, Enum):
    info = "info"
    warning = "warning"
    critical = "critical"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class Notification(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: NotificationType
    title: str
    message: str
    read: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    link: Optional[str] = None
    severity: Severity = Severity.info


class NotificationCreate(BaseModel):
    recipient_email: str
    type: NotificationType
    title: str
    message: str
    link: Optional[str] = None
    severity: Severity = Severity.info


class NotificationList(BaseModel):
    total: int
    unread_count: int
    notifications: list[Notification]


class PreferenceChannel(BaseModel):
    email: bool = True
    in_app: bool = True


class NotificationPreferences(BaseModel):
    preferences: dict[NotificationType, PreferenceChannel] = Field(
        default_factory=lambda: {t: PreferenceChannel() for t in NotificationType}
    )


# ---------------------------------------------------------------------------
# In-memory stores
# ---------------------------------------------------------------------------

# email -> list of Notification
_notifications: dict[str, list[Notification]] = defaultdict(list)

# email -> NotificationPreferences
_preferences: dict[str, NotificationPreferences] = {}


# ---------------------------------------------------------------------------
# Public helper -- importable by other modules
# ---------------------------------------------------------------------------


def send_notification(
    email: str,
    type: str,
    title: str,
    message: str,
    link: Optional[str] = None,
    severity: str = "info",
) -> Notification:
    """
    Push a notification into the in-app store for the given user.

    This is the primary integration point for other services (e.g. the
    compliance agent, drift detector, or scheduler) to create notifications
    without going through the HTTP layer.

    Returns the created Notification object.
    """
    notification = Notification(
        type=NotificationType(type),
        title=title,
        message=message,
        link=link,
        severity=Severity(severity),
    )
    _notifications[email].append(notification)
    logger.info(
        "Notification sent to %s: [%s] %s",
        email,
        notification.severity.value,
        title,
    )
    return notification


# ---------------------------------------------------------------------------
# Helper to locate a notification by id within a user's list
# ---------------------------------------------------------------------------


def _find_notification(
    email: str, notification_id: str
) -> tuple[int, Notification]:
    """Return (index, notification) or raise 404."""
    for idx, n in enumerate(_notifications[email]):
        if n.id == notification_id:
            return idx, n
    raise HTTPException(status_code=404, detail="Notification not found")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=NotificationList)
def list_notifications(
    unread_only: bool = Query(False, description="Return only unread notifications"),
    type: Optional[NotificationType] = Query(None, description="Filter by notification type"),
    limit: int = Query(50, ge=1, le=200, description="Max notifications to return"),
    current_user: str = Depends(verify_token),
):
    """List notifications for the authenticated user."""
    items = _notifications[current_user]

    if unread_only:
        items = [n for n in items if not n.read]
    if type is not None:
        items = [n for n in items if n.type == type]

    # Most recent first
    items = sorted(items, key=lambda n: n.created_at, reverse=True)

    unread_count = sum(1 for n in _notifications[current_user] if not n.read)

    return NotificationList(
        total=len(items),
        unread_count=unread_count,
        notifications=items[:limit],
    )


@router.post("", response_model=Notification, status_code=201)
def create_notification(
    body: NotificationCreate,
    _current_user: str = Depends(verify_token),
):
    """
    Create a notification for a specific recipient.

    Intended for internal service-to-service use. The caller must be
    authenticated but the notification is delivered to `recipient_email`.
    """
    return send_notification(
        email=body.recipient_email,
        type=body.type.value,
        title=body.title,
        message=body.message,
        link=body.link,
        severity=body.severity.value,
    )


@router.patch("/{notification_id}/read", response_model=Notification)
def mark_read(
    notification_id: str,
    current_user: str = Depends(verify_token),
):
    """Mark a single notification as read."""
    _idx, notification = _find_notification(current_user, notification_id)
    notification.read = True
    return notification


@router.post("/read-all", response_model=dict)
def mark_all_read(
    current_user: str = Depends(verify_token),
):
    """Mark every notification for the current user as read."""
    count = 0
    for n in _notifications[current_user]:
        if not n.read:
            n.read = True
            count += 1
    return {"marked_read": count}


@router.delete("/{notification_id}", status_code=204)
def delete_notification(
    notification_id: str,
    current_user: str = Depends(verify_token),
):
    """Delete a single notification."""
    idx, _notification = _find_notification(current_user, notification_id)
    _notifications[current_user].pop(idx)
    return None


@router.get("/preferences", response_model=NotificationPreferences)
def get_preferences(
    current_user: str = Depends(verify_token),
):
    """Get the notification delivery preferences for the authenticated user."""
    if current_user not in _preferences:
        _preferences[current_user] = NotificationPreferences()
    return _preferences[current_user]


@router.put("/preferences", response_model=NotificationPreferences)
def update_preferences(
    body: NotificationPreferences,
    current_user: str = Depends(verify_token),
):
    """Replace notification delivery preferences for the authenticated user."""
    _preferences[current_user] = body
    return _preferences[current_user]
