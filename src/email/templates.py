"""HTML email templates for GovernLayer transactional emails.

Dark theme matching GovernLayer branding:
  --bg: #0a0e1a
  --surface: #111827
  --border: #1e293b
  --accent: #00ff88
  --accent-blue: #3b82f6
  --text: #e2e8f0
  --muted: #94a3b8
"""

from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Base layout
# ---------------------------------------------------------------------------

_BASE_HEAD = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
</head>
<body style="margin:0;padding:0;background:#0a0e1a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#0a0e1a">
<tr><td align="center" style="padding:40px 16px">
<table role="presentation" width="560" cellspacing="0" cellpadding="0" style="max-width:560px;width:100%">
"""

_LOGO_HEADER = """\
<tr><td align="center" style="padding-bottom:32px">
<table role="presentation" cellspacing="0" cellpadding="0">
<tr>
<td style="background:#00ff88;width:10px;height:32px;border-radius:3px"></td>
<td style="padding-left:12px">
<span style="color:#ffffff;font-size:22px;font-weight:700;letter-spacing:-0.5px">GovernLayer</span>
</td>
</tr>
</table>
<p style="color:#94a3b8;font-size:12px;margin:8px 0 0;letter-spacing:0.5px">AUTONOMOUS AI GOVERNANCE</p>
</td></tr>
"""

_FOOTER = """\
<tr><td style="padding-top:32px;border-top:1px solid #1e293b">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0">
<tr><td align="center">
<p style="color:#64748b;font-size:12px;line-height:1.6;margin:0">
&copy; {year} GovernLayer Inc. All rights reserved.
</p>
<p style="color:#475569;font-size:11px;line-height:1.6;margin:8px 0 0">
You received this because your email is associated with a GovernLayer account.<br>
<a href="https://governlayer.ai/settings/notifications" style="color:#3b82f6;text-decoration:none">Manage notification preferences</a>
&nbsp;&middot;&nbsp;
<a href="https://governlayer.ai/unsubscribe" style="color:#3b82f6;text-decoration:none">Unsubscribe</a>
</p>
</td></tr>
</table>
</td></tr>
"""

_BASE_TAIL = """\
</table>
</td></tr>
</table>
</body>
</html>
"""


def _wrap(title: str, content: str) -> str:
    """Wrap content in the base email template."""
    year = datetime.now(timezone.utc).year
    return (
        _BASE_HEAD.format(title=title)
        + _LOGO_HEADER
        + content
        + _FOOTER.format(year=year)
        + _BASE_TAIL
    )


# ---------------------------------------------------------------------------
# Reusable components
# ---------------------------------------------------------------------------

def _card(inner: str, border_left_color: str = "") -> str:
    """Wrap content in a card block."""
    border = f"border-left:4px solid {border_left_color};" if border_left_color else ""
    return f"""\
<tr><td style="background:#111827;border:1px solid #1e293b;border-radius:8px;padding:28px;{border}">
{inner}
</td></tr>
"""


def _button(url: str, label: str, color: str = "#00ff88", text_color: str = "#000000") -> str:
    """Generate a CTA button."""
    return f"""\
<div style="text-align:center;margin:24px 0">
<a href="{url}" style="display:inline-block;background:{color};color:{text_color};padding:12px 32px;border-radius:6px;text-decoration:none;font-weight:700;font-size:14px;letter-spacing:0.3px">{label}</a>
</div>
"""


def _code_block(text: str) -> str:
    """Inline code snippet."""
    return f'<code style="background:#0a0e1a;color:#00ff88;padding:2px 8px;border-radius:4px;font-size:13px">{text}</code>'


def _badge(label: str, color: str) -> str:
    """Colored badge/pill."""
    return f'<span style="display:inline-block;background:{color};color:#000;padding:3px 12px;border-radius:4px;font-size:12px;font-weight:700;letter-spacing:0.5px">{label}</span>'


# ---------------------------------------------------------------------------
# Email templates
# ---------------------------------------------------------------------------

def welcome(email: str, name: str) -> tuple[str, str]:
    """Welcome / onboarding email for new signups. Returns (subject, html)."""
    subject = f"Welcome to GovernLayer Beta -- Your Onboarding Guide"
    api_url = "https://web-production-bdd26.up.railway.app"

    def _step(num: str, color: str, title: str) -> str:
        return (
            f'<h3 style="color:#e2e8f0;font-size:16px;margin:28px 0 12px">'
            f'<span style="background:{color};color:#fff;width:24px;height:24px;'
            f'border-radius:50%;display:inline-block;text-align:center;line-height:24px;'
            f'font-size:13px;font-weight:700;margin-right:8px">{num}</span>'
            f'{title}</h3>'
        )

    def _api_block(method_path: str, body: str = "", note: str = "") -> str:
        parts = f'<div style="background:#0a0e1a;border:1px solid #1e293b;border-radius:6px;padding:16px;margin:0 0 8px">'
        parts += f'<code style="color:#94a3b8;font-size:13px;display:block">{method_path}</code>'
        if body:
            parts += f'<code style="color:#64748b;font-size:12px;display:block;margin-top:8px">{body}</code>'
        if note:
            parts += f'<p style="color:#64748b;font-size:12px;margin:8px 0 0">{note}</p>'
        parts += '</div>'
        return parts

    content = _card(f"""\
<h2 style="color:#e2e8f0;margin:0 0 8px;font-size:22px">Welcome to the Founding Cohort</h2>
<p style="color:#94a3b8;line-height:1.7;margin:0 0 20px">
Your account {_code_block(email)} for <strong style="color:#e2e8f0">{name}</strong> is ready.
You are one of our earliest enterprise beta partners. Here is how to get your environment set up.
</p>

<div style="background:linear-gradient(135deg,rgba(59,130,246,0.08),rgba(16,185,129,0.08));border:1px solid rgba(59,130,246,0.15);border-radius:6px;padding:16px;margin:0 0 8px">
<p style="color:#60a5fa;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;margin:0 0 6px">Your API Base URL</p>
<code style="color:#00ff88;font-size:14px">{api_url}</code>
</div>

{_step("1", "#3b82f6", "Log In")}
{_api_block(
    "POST /auth/login",
    '{{"email": "' + email + '", "password": "your-password"}}',
    "Returns a JWT token. Use it in the Authorization header for the next steps."
)}

{_step("2", "#8b5cf6", "Create Your Organization")}
{_api_block(
    "POST /v1/enterprise/orgs",
    '{{"name": "' + name + '", "slug": "' + name.lower().replace(" ", "-") + '"}}',
    "This creates your isolated tenant. All your data is scoped to your org."
)}

{_step("3", "#10b981", "Generate Your API Key")}
{_api_block(
    "POST /v1/enterprise/orgs/" + name.lower().replace(" ", "-") + "/api-keys",
    '{{"name": "production", "scopes": "govern,audit,risk,scan,read"}}',
    '<strong style="color:#f59e0b">Save the API key -- it is only shown once.</strong> Use as: Authorization: Bearer gl_xxx'
)}

{_step("4", "#f59e0b", "Start Governing")}
<div style="background:#0a0e1a;border:1px solid #1e293b;border-radius:6px;padding:16px">
<p style="color:#94a3b8;font-size:13px;margin:0 0 12px">With your API key, you can now:</p>
<table role="presentation" width="100%" cellspacing="0" cellpadding="0">
<tr><td style="color:#00ff88;font-size:12px;padding:6px 0;border-bottom:1px solid #1e293b;font-family:monospace">POST /v1/models</td><td style="color:#94a3b8;font-size:12px;padding:6px 0;border-bottom:1px solid #1e293b">Register your AI models</td></tr>
<tr><td style="color:#00ff88;font-size:12px;padding:6px 0;border-bottom:1px solid #1e293b;font-family:monospace">POST /v1/agents</td><td style="color:#94a3b8;font-size:12px;padding:6px 0;border-bottom:1px solid #1e293b">Register your AI agents</td></tr>
<tr><td style="color:#00ff88;font-size:12px;padding:6px 0;border-bottom:1px solid #1e293b;font-family:monospace">POST /v1/policies</td><td style="color:#94a3b8;font-size:12px;padding:6px 0;border-bottom:1px solid #1e293b">Set governance policies</td></tr>
<tr><td style="color:#00ff88;font-size:12px;padding:6px 0;border-bottom:1px solid #1e293b;font-family:monospace">POST /v1/govern</td><td style="color:#94a3b8;font-size:12px;padding:6px 0;border-bottom:1px solid #1e293b">Run full governance pipeline</td></tr>
<tr><td style="color:#00ff88;font-size:12px;padding:6px 0;border-bottom:1px solid #1e293b;font-family:monospace">GET /v1/dashboard</td><td style="color:#94a3b8;font-size:12px;padding:6px 0;border-bottom:1px solid #1e293b">Your org health at a glance</td></tr>
<tr><td style="color:#00ff88;font-size:12px;padding:6px 0;font-family:monospace">POST /v1/scan</td><td style="color:#94a3b8;font-size:12px;padding:6px 0">Quick deterministic scan (instant)</td></tr>
</table>
</div>

<div style="background:linear-gradient(135deg,rgba(16,185,129,0.06),rgba(59,130,246,0.06));border:1px solid rgba(16,185,129,0.15);border-radius:6px;padding:16px;margin:24px 0 0">
<h4 style="color:#10b981;margin:0 0 8px;font-size:14px">Included in your beta access:</h4>
<ul style="color:#94a3b8;font-size:13px;line-height:2;margin:0;padding-left:20px">
<li>Full API access -- 29 compliance frameworks (EU AI Act, SOC 2, NIST, ISO 42001, HIPAA, GDPR)</li>
<li>Real-time drift detection on AI reasoning traces</li>
<li>Tamper-proof hash-chained audit ledger</li>
<li>Deterministic 6-dimension risk scoring</li>
<li>Shadow AI discovery scanning</li>
<li>Webhook notifications (HMAC-signed)</li>
<li>Direct support from the founding team</li>
</ul>
</div>
""")

    content += f"""\
<tr><td style="padding-top:24px;text-align:center">
{_button(api_url + "/docs", "Explore the API Docs", color="#3b82f6", text_color="#ffffff")}
<p style="color:#64748b;font-size:13px;margin:8px 0 0">
Questions? Reply to this email or reach out to
<a href="mailto:founders@governlayer.ai" style="color:#3b82f6;text-decoration:none">founders@governlayer.ai</a>
</p>
</td></tr>
"""
    return subject, _wrap(subject, content)


def password_reset(email: str, reset_token: str) -> tuple[str, str]:
    """Password reset email. Returns (subject, html)."""
    subject = "GovernLayer -- Password Reset"
    reset_url = f"https://governlayer.ai/reset?token={reset_token}"
    content = _card(f"""\
<h2 style="color:#e2e8f0;margin:0 0 12px;font-size:20px">Password Reset</h2>
<p style="color:#94a3b8;line-height:1.7;margin:0 0 16px">
We received a request to reset the password for <strong style="color:#e2e8f0">{email}</strong>.
</p>
{_button(reset_url, "Reset Password")}
<p style="color:#64748b;font-size:13px;margin:16px 0 0">
Or use this token directly: {_code_block(reset_token)}
</p>
<p style="color:#64748b;font-size:12px;margin:12px 0 0">
This link expires in 1 hour. If you did not request this, ignore this email.
</p>
""")
    return subject, _wrap(subject, content)


def api_key_created(email: str, key_prefix: str) -> tuple[str, str]:
    """API key provisioned notification. Returns (subject, html)."""
    subject = "GovernLayer -- New API Key Created"
    content = _card(f"""\
<h2 style="color:#e2e8f0;margin:0 0 12px;font-size:20px">API Key Created</h2>
<p style="color:#94a3b8;line-height:1.7;margin:0 0 16px">
A new API key has been provisioned for your account.
</p>
<div style="background:#0a0e1a;border:1px solid #1e293b;border-radius:6px;padding:16px;margin:16px 0">
<p style="color:#94a3b8;font-size:13px;margin:0">
Key prefix: {_code_block(key_prefix + "...")}
</p>
</div>
<p style="color:#64748b;font-size:13px;margin:0">
Store your full key securely -- it will not be shown again.
If you did not create this key, revoke it immediately in your
<a href="https://governlayer.ai/settings/api-keys" style="color:#3b82f6;text-decoration:none">dashboard</a>.
</p>
""")
    return subject, _wrap(subject, content)


def escalation_alert(
    email: str,
    decision_id: str,
    violation_type: str,
    sla_deadline: str,
) -> tuple[str, str]:
    """HITL escalation notification. Returns (subject, html)."""
    subject = f"GovernLayer -- Escalation Required: {violation_type}"
    severity_map = {
        "BLOCKING": "#ef4444",
        "CRITICAL": "#f97316",
        "WARNING": "#eab308",
    }
    color = severity_map.get(violation_type.upper(), "#f97316")
    content = _card(
        f"""\
<div style="margin-bottom:16px">
{_badge(violation_type.upper(), color)}
<span style="color:#64748b;font-size:13px;margin-left:8px">Decision #{decision_id}</span>
</div>
<h2 style="color:#e2e8f0;margin:0 0 12px;font-size:20px">Human Review Required</h2>
<p style="color:#94a3b8;line-height:1.7;margin:0 0 16px">
An AI governance decision has been flagged for human-in-the-loop review.
A <strong style="color:#e2e8f0">{violation_type}</strong> violation was detected
and requires your attention before the SLA deadline.
</p>
<div style="background:#0a0e1a;border:1px solid #1e293b;border-radius:6px;padding:16px;margin:16px 0">
<table role="presentation" width="100%" cellspacing="0" cellpadding="4">
<tr>
<td style="color:#64748b;font-size:13px;width:120px">Decision ID</td>
<td style="color:#e2e8f0;font-size:13px">{_code_block(decision_id)}</td>
</tr>
<tr>
<td style="color:#64748b;font-size:13px">Violation</td>
<td style="color:#e2e8f0;font-size:13px">{violation_type}</td>
</tr>
<tr>
<td style="color:#64748b;font-size:13px">SLA Deadline</td>
<td style="color:#ef4444;font-size:13px;font-weight:600">{sla_deadline}</td>
</tr>
</table>
</div>
{_button("https://governlayer.ai/dashboard#escalations", "Review Now", color="#f97316")}
""",
        border_left_color=color,
    )
    return subject, _wrap(subject, content)


def billing_receipt(email: str, amount: str, plan: str) -> tuple[str, str]:
    """Payment confirmation email. Returns (subject, html)."""
    subject = f"GovernLayer -- Payment Receipt ({plan.title()} Plan)"
    content = _card(f"""\
<h2 style="color:#e2e8f0;margin:0 0 12px;font-size:20px">Payment Received</h2>
<p style="color:#94a3b8;line-height:1.7;margin:0 0 16px">
Thank you for your payment. Here is your receipt.
</p>
<div style="background:#0a0e1a;border:1px solid #1e293b;border-radius:6px;padding:16px;margin:16px 0">
<table role="presentation" width="100%" cellspacing="0" cellpadding="4">
<tr>
<td style="color:#64748b;font-size:13px;width:100px">Plan</td>
<td style="color:#e2e8f0;font-size:13px;font-weight:600">{plan.title()}</td>
</tr>
<tr>
<td style="color:#64748b;font-size:13px">Amount</td>
<td style="color:#00ff88;font-size:18px;font-weight:700">{amount}</td>
</tr>
<tr>
<td style="color:#64748b;font-size:13px">Date</td>
<td style="color:#e2e8f0;font-size:13px">{datetime.now(timezone.utc).strftime("%B %d, %Y")}</td>
</tr>
</table>
</div>
{_button("https://governlayer.ai/billing", "View Billing Portal", color="#3b82f6", text_color="#ffffff")}
<p style="color:#64748b;font-size:12px;margin:8px 0 0">
Questions about billing? Contact <a href="mailto:billing@governlayer.ai" style="color:#3b82f6;text-decoration:none">billing@governlayer.ai</a>.
</p>
""")
    return subject, _wrap(subject, content)
