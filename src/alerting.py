"""Lightweight alerting helper.

Sends a message to a Slack incoming-webhook when SLACK_ALERT_WEBHOOK is set.
Silently no-ops otherwise, so calling `send_alert()` is safe from anywhere
without a guard.

Intentionally kept dependency-free (uses urllib) so it can be called from
signal handlers, background daemons, or the request path without pulling
new packages.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request

from src.config import get_settings

logger = logging.getLogger(__name__)


def send_alert(title: str, body: str, level: str = "error") -> bool:
    """Fire an alert; return True on success, False on any failure.

    Args:
        title: One-line summary rendered as bold text.
        body: Longer description, rendered as monospace block.
        level: "info" | "warn" | "error" | "critical" — controls the emoji.
    """
    s = get_settings()
    if not s.slack_alert_webhook:
        return False

    emoji = {
        "info": ":information_source:",
        "warn": ":warning:",
        "error": ":rotating_light:",
        "critical": ":fire:",
    }.get(level, ":bell:")

    payload = {
        "text": f"{emoji} *[{s.environment.upper()}] {title}*",
        "attachments": [
            {
                "color": {"info": "#3b82f6", "warn": "#f59e0b",
                          "error": "#ef4444", "critical": "#7c2d12"}.get(level, "#64748b"),
                "text": body[:2000],
                "mrkdwn_in": ["text"],
            }
        ],
    }

    try:
        req = urllib.request.Request(
            s.slack_alert_webhook,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
        logger.warning("send_alert failed: %s", exc)
        return False
