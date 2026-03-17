"""Email templates for GovernLayer notifications."""

BRAND_HEADER = """
<div style="background:#0a0a0f;padding:32px;font-family:-apple-system,system-ui,sans-serif">
<div style="max-width:560px;margin:0 auto">
<div style="text-align:center;margin-bottom:24px">
<h1 style="color:#00ff88;font-size:24px;margin:0">GovernLayer</h1>
<p style="color:#888;font-size:13px;margin:4px 0 0">The Governance Layer for Agentic AI</p>
</div>
"""

BRAND_FOOTER = """
<div style="text-align:center;margin-top:32px;padding-top:16px;border-top:1px solid #222">
<p style="color:#666;font-size:12px;margin:0">&copy; 2026 GovernLayer. All rights reserved.</p>
<p style="color:#555;font-size:11px;margin:4px 0 0">You received this because your email is associated with a GovernLayer account.</p>
</div>
</div></div>
"""


def password_reset_email(token: str, email: str) -> tuple[str, str]:
    """Returns (subject, html_body) for password reset."""
    subject = "GovernLayer — Password Reset"
    # In production, this would be a real URL like https://app.governlayer.ai/reset?token=xxx
    reset_url = f"https://governlayer.ai/reset?token={token}"
    html = BRAND_HEADER + f"""
<div style="background:#111;border:1px solid #222;border-radius:8px;padding:24px">
<h2 style="color:#fff;margin:0 0 12px;font-size:18px">Password Reset Request</h2>
<p style="color:#aaa;line-height:1.6;margin:0 0 20px">
We received a request to reset the password for <strong style="color:#fff">{email}</strong>.
</p>
<div style="text-align:center;margin:24px 0">
<a href="{reset_url}" style="display:inline-block;background:#00ff88;color:#000;padding:12px 32px;border-radius:6px;text-decoration:none;font-weight:700;font-size:14px">Reset Password</a>
</div>
<p style="color:#666;font-size:13px;margin:0">
Or use this token directly: <code style="background:#1a1a2e;color:#00ff88;padding:2px 8px;border-radius:4px">{token}</code>
</p>
<p style="color:#666;font-size:13px;margin:12px 0 0">This link expires in 1 hour. If you didn't request this, ignore this email.</p>
</div>
""" + BRAND_FOOTER
    return subject, html


def incident_alert_email(incident_title: str, severity: str, incident_id: int) -> tuple[str, str]:
    """Returns (subject, html_body) for incident alerts."""
    severity_colors = {"critical": "#ff4444", "high": "#ff8800", "medium": "#ffcc00", "low": "#00ff88"}
    color = severity_colors.get(severity, "#888")
    subject = f"GovernLayer Incident [{severity.upper()}] — {incident_title}"
    html = BRAND_HEADER + f"""
<div style="background:#111;border:1px solid #222;border-radius:8px;padding:24px;border-left:4px solid {color}">
<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px">
<span style="background:{color};color:#000;padding:2px 10px;border-radius:4px;font-size:12px;font-weight:700">{severity.upper()}</span>
<span style="color:#888;font-size:13px">Incident #{incident_id}</span>
</div>
<h2 style="color:#fff;margin:0 0 16px;font-size:18px">{incident_title}</h2>
<div style="text-align:center;margin:20px 0">
<a href="https://governlayer.ai/dashboard#incidents" style="display:inline-block;background:#222;color:#00ff88;padding:10px 24px;border-radius:6px;text-decoration:none;font-weight:600;font-size:13px;border:1px solid #333">View in Dashboard</a>
</div>
</div>
""" + BRAND_FOOTER
    return subject, html


def welcome_email(email: str, company: str) -> tuple[str, str]:
    """Returns (subject, html_body) for new user welcome."""
    subject = f"Welcome to GovernLayer, {company}"
    html = BRAND_HEADER + f"""
<div style="background:#111;border:1px solid #222;border-radius:8px;padding:24px">
<h2 style="color:#fff;margin:0 0 12px;font-size:18px">Welcome to GovernLayer</h2>
<p style="color:#aaa;line-height:1.6;margin:0 0 16px">
Your account <strong style="color:#fff">{email}</strong> for <strong style="color:#00ff88">{company}</strong> is ready.
</p>
<div style="background:#0a0a1a;border:1px solid #1a1a2e;border-radius:6px;padding:16px;margin:16px 0">
<p style="color:#888;font-size:13px;margin:0 0 8px">Quick start:</p>
<ol style="color:#aaa;font-size:13px;line-height:1.8;margin:0;padding-left:20px">
<li>Create an organization: <code style="color:#00ff88">POST /v1/enterprise/orgs</code></li>
<li>Generate an API key: <code style="color:#00ff88">POST /v1/enterprise/orgs/{{slug}}/api-keys</code></li>
<li>Run your first governance check: <code style="color:#00ff88">POST /v1/govern</code></li>
</ol>
</div>
<div style="text-align:center;margin:20px 0">
<a href="https://governlayer.ai/docs" style="display:inline-block;background:#00ff88;color:#000;padding:12px 32px;border-radius:6px;text-decoration:none;font-weight:700;font-size:14px">Read the Docs</a>
</div>
</div>
""" + BRAND_FOOTER
    return subject, html


def webhook_failure_email(webhook_url: str, event_type: str, status_code: int) -> tuple[str, str]:
    """Returns (subject, html_body) for webhook delivery failure."""
    subject = "GovernLayer — Webhook Delivery Failed"
    html = BRAND_HEADER + f"""
<div style="background:#111;border:1px solid #222;border-radius:8px;padding:24px;border-left:4px solid #ff4444">
<h2 style="color:#fff;margin:0 0 16px;font-size:18px">Webhook Delivery Failed</h2>
<div style="background:#0a0a1a;border:1px solid #1a1a2e;border-radius:6px;padding:16px;margin:12px 0">
<div style="color:#888;font-size:13px;margin-bottom:8px">Event: <span style="color:#fff">{event_type}</span></div>
<div style="color:#888;font-size:13px;margin-bottom:8px">URL: <code style="color:#ff8800">{webhook_url}</code></div>
<div style="color:#888;font-size:13px">Status: <span style="color:#ff4444">{status_code}</span></div>
</div>
<p style="color:#666;font-size:13px;margin:12px 0 0">Check your webhook endpoint and update it at <code style="color:#00ff88">PUT /v1/enterprise/orgs/{{slug}}/webhooks</code>.</p>
</div>
""" + BRAND_FOOTER
    return subject, html
