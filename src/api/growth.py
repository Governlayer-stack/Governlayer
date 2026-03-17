"""Go-to-market endpoints — waitlist, demo booking, legal pages, onboarding."""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from src.models.database import SessionLocal, Base
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean

router = APIRouter(tags=["Growth"])


# --- Waitlist Model ---

class WaitlistEntry(Base):
    __tablename__ = "waitlist"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), nullable=False, unique=True, index=True)
    company = Column(String(255))
    role = Column(String(100))
    use_case = Column(Text)
    source = Column(String(100), default="website")
    status = Column(String(20), default="pending")  # pending, contacted, converted
    created_at = Column(DateTime, default=datetime.utcnow)


class DemoRequest(Base):
    __tablename__ = "demo_requests"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False, index=True)
    company = Column(String(255))
    role = Column(String(100))
    team_size = Column(String(50))
    use_case = Column(Text)
    frameworks_interested = Column(Text)
    status = Column(String(20), default="pending")  # pending, scheduled, completed
    created_at = Column(DateTime, default=datetime.utcnow)


# --- Schemas ---

class WaitlistRequest(BaseModel):
    email: str = Field(..., min_length=5)
    company: Optional[str] = None
    role: Optional[str] = None
    use_case: Optional[str] = None


class DemoBookingRequest(BaseModel):
    name: str = Field(..., min_length=2)
    email: str = Field(..., min_length=5)
    company: Optional[str] = None
    role: Optional[str] = None
    team_size: Optional[str] = None
    use_case: Optional[str] = None
    frameworks_interested: Optional[str] = None


# --- Waitlist ---

@router.post("/v1/waitlist")
def join_waitlist(data: WaitlistRequest):
    """Join the GovernLayer waitlist for early access and enterprise features."""
    db = SessionLocal()
    try:
        existing = db.query(WaitlistEntry).filter(WaitlistEntry.email == data.email).first()
        if existing:
            return {"message": "You're already on the list!", "position": existing.id}

        entry = WaitlistEntry(
            email=data.email,
            company=data.company,
            role=data.role,
            use_case=data.use_case,
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)

        total = db.query(WaitlistEntry).count()
        return {
            "message": "Welcome to the GovernLayer waitlist!",
            "position": total,
            "next_steps": [
                "We'll reach out within 24 hours for onboarding",
                "Check your email for getting started guide",
                "Try the live API now at /docs",
            ],
        }
    finally:
        db.close()


@router.get("/v1/waitlist/count")
def waitlist_count():
    """Get current waitlist size (public social proof)."""
    db = SessionLocal()
    try:
        total = db.query(WaitlistEntry).count()
        return {"total": total}
    finally:
        db.close()


# --- Demo Booking ---

@router.post("/v1/demo")
def book_demo(data: DemoBookingRequest):
    """Request a product demo from the GovernLayer team."""
    db = SessionLocal()
    try:
        existing = db.query(DemoRequest).filter(
            DemoRequest.email == data.email, DemoRequest.status == "pending"
        ).first()
        if existing:
            return {"message": "You already have a demo request pending. We'll be in touch soon!"}

        demo = DemoRequest(
            name=data.name,
            email=data.email,
            company=data.company,
            role=data.role,
            team_size=data.team_size,
            use_case=data.use_case,
            frameworks_interested=data.frameworks_interested,
        )
        db.add(demo)
        db.commit()
        db.refresh(demo)

        return {
            "message": "Demo request received! Our team will reach out within 24 hours.",
            "demo_id": demo.id,
            "what_to_expect": [
                "15-minute personalized walkthrough",
                "Shadow AI scan of your organization",
                "Compliance gap analysis for your frameworks",
                "Custom pricing based on your needs",
            ],
        }
    finally:
        db.close()


@router.get("/v1/demo")
def demo_info():
    """Demo booking information page."""
    return HTMLResponse("""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Book a Demo — GovernLayer</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',sans-serif;background:#08080c;color:#eeeef0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
.card{max-width:560px;width:100%;background:#0e0e14;border:1px solid rgba(255,255,255,0.06);border-radius:16px;padding:40px}
h1{font-size:28px;font-weight:800;margin-bottom:8px;letter-spacing:-0.5px}
.sub{color:#7a7a8e;font-size:15px;margin-bottom:32px;line-height:1.6}
.field{margin-bottom:16px}
label{display:block;font-size:12px;font-weight:600;color:#7a7a8e;margin-bottom:6px;text-transform:uppercase;letter-spacing:0.5px}
input,select,textarea{width:100%;padding:12px 16px;background:#08080c;border:1px solid rgba(255,255,255,0.1);border-radius:10px;color:#eeeef0;font-size:14px;font-family:inherit;outline:none}
input:focus,select:focus,textarea:focus{border-color:#00ffaa}
textarea{min-height:80px;resize:vertical}
select{appearance:auto}
.row{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.btn{width:100%;padding:14px;background:linear-gradient(135deg,#00ffaa,#7b61ff);color:#08080c;font-size:15px;font-weight:700;border:none;border-radius:10px;cursor:pointer;margin-top:24px;transition:opacity 0.2s}
.btn:hover{opacity:0.9}
.msg{margin-top:16px;font-size:14px;text-align:center;min-height:20px}
.back{display:block;text-align:center;margin-top:20px;color:#7a7a8e;font-size:13px}
.back:hover{color:#eeeef0}
.checks{margin-top:24px;padding-top:24px;border-top:1px solid rgba(255,255,255,0.06)}
.checks h3{font-size:14px;font-weight:700;margin-bottom:12px}
.check{display:flex;align-items:flex-start;gap:10px;font-size:13px;color:#7a7a8e;padding:6px 0}
.check::before{content:'';width:16px;height:16px;border-radius:50%;border:1.5px solid #00ffaa;flex-shrink:0;margin-top:1px}
</style></head><body>
<div class="card">
<h1>Book a Demo</h1>
<p class="sub">See how GovernLayer can govern your AI systems. Our team will walk you through shadow AI discovery, compliance reporting, and policy enforcement.</p>
<div class="row"><div class="field"><label>Name</label><input id="dName" placeholder="Jane Smith"></div>
<div class="field"><label>Email</label><input id="dEmail" type="email" placeholder="jane@company.com"></div></div>
<div class="row"><div class="field"><label>Company</label><input id="dCompany" placeholder="Acme Corp"></div>
<div class="field"><label>Role</label><select id="dRole"><option value="">Select role</option><option>CISO</option><option>VP Engineering</option><option>Head of ML/AI</option><option>Compliance Officer</option><option>CTO</option><option>Product Manager</option><option>Other</option></select></div></div>
<div class="field"><label>Team Size</label><select id="dSize"><option value="">Select size</option><option>1-10</option><option>11-50</option><option>51-200</option><option>201-1000</option><option>1000+</option></select></div>
<div class="field"><label>What do you want to govern?</label><textarea id="dUseCase" placeholder="e.g., We have 15 AI models in production and need EU AI Act compliance..."></textarea></div>
<button class="btn" onclick="submitDemo()">Request Demo</button>
<div class="msg" id="dMsg"></div>
<div class="checks"><h3>What you'll get</h3>
<div class="check">15-minute personalized product walkthrough</div>
<div class="check">Live shadow AI scan of your organization</div>
<div class="check">Compliance gap analysis for your frameworks</div>
<div class="check">Custom pricing based on your needs</div></div>
<a href="/" class="back">Back to GovernLayer</a>
</div>
<script>
async function submitDemo(){
  const msg=document.getElementById('dMsg');
  const body={name:document.getElementById('dName').value,email:document.getElementById('dEmail').value,
    company:document.getElementById('dCompany').value,role:document.getElementById('dRole').value,
    team_size:document.getElementById('dSize').value,use_case:document.getElementById('dUseCase').value};
  if(!body.name||!body.email){msg.innerHTML='<span style="color:#ef4444">Name and email are required</span>';return;}
  msg.innerHTML='<span style="color:#7a7a8e">Submitting...</span>';
  try{const r=await fetch('/v1/demo',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d=await r.json();
    if(r.ok)msg.innerHTML='<span style="color:#00ffaa">'+d.message+'</span>';
    else msg.innerHTML='<span style="color:#ef4444">'+(d.detail||'Error')+'</span>';
  }catch(e){msg.innerHTML='<span style="color:#ef4444">Network error</span>';}
}
</script></body></html>""")


# --- Legal Pages ---

TERMS_OF_SERVICE = """
GovernLayer Terms of Service
Last Updated: March 16, 2026

1. ACCEPTANCE OF TERMS
By accessing or using the GovernLayer platform ("Service"), you agree to be bound by these Terms of Service ("Terms"). If you are using the Service on behalf of an organization, you represent that you have authority to bind that organization to these Terms.

2. SERVICE DESCRIPTION
GovernLayer provides an AI governance platform including compliance auditing, behavioral drift detection, risk scoring, agent registry, shadow AI discovery, policy enforcement, and immutable audit ledgers via REST API and dashboard interfaces.

3. ACCOUNTS AND API KEYS
- You are responsible for maintaining the security of your API keys and account credentials.
- API keys should not be shared, published, or embedded in client-side code.
- You must notify us immediately of any unauthorized use of your account.
- We reserve the right to suspend accounts that violate these Terms.

4. ACCEPTABLE USE
You agree not to:
- Use the Service for any unlawful purpose or in violation of applicable laws.
- Attempt to gain unauthorized access to the Service or its systems.
- Interfere with or disrupt the Service or servers connected to the Service.
- Reverse engineer, decompile, or disassemble any part of the Service.
- Exceed your plan's rate limits or circumvent usage restrictions.
- Use the Service to process data you do not have rights to process.

5. DATA PROCESSING
- GovernLayer processes data you submit through the API for governance purposes.
- We do not use your data to train AI models.
- Audit logs are stored in our immutable hash-chained ledger.
- Data retention follows your plan's configured policies.
- See our Privacy Policy for full data handling details.

6. PLANS AND BILLING
- Free tier: 20 requests/minute, all frameworks, no payment required.
- Paid plans: Billed monthly via Stripe. Prices as published on our website.
- Upgrades take effect immediately. Downgrades take effect at next billing cycle.
- We reserve the right to modify pricing with 30 days notice.

7. SERVICE LEVEL AGREEMENT (SLA)
- Enterprise plans include 99.9% uptime SLA.
- SLA credits are calculated based on monthly downtime exceeding the target.
- Scheduled maintenance windows are excluded from SLA calculations.
- See /v1/enterprise/sla for current SLA metrics.

8. INTELLECTUAL PROPERTY
- GovernLayer retains all rights to the Service, including all software, APIs, and documentation.
- You retain all rights to your data submitted through the Service.
- Governance reports, risk scores, and audit records generated by the Service are your property.

9. LIMITATION OF LIABILITY
TO THE MAXIMUM EXTENT PERMITTED BY LAW, GOVERNLAYER SHALL NOT BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES, OR ANY LOSS OF PROFITS OR REVENUES, WHETHER INCURRED DIRECTLY OR INDIRECTLY. OUR TOTAL LIABILITY SHALL NOT EXCEED THE AMOUNT PAID BY YOU IN THE 12 MONTHS PRECEDING THE CLAIM.

10. INDEMNIFICATION
You agree to indemnify and hold GovernLayer harmless from any claims, damages, or expenses arising from your use of the Service or violation of these Terms.

11. TERMINATION
- You may terminate your account at any time by contacting us.
- We may suspend or terminate accounts for violations of these Terms.
- Upon termination, we will provide a 30-day window for data export.

12. MODIFICATIONS
We may modify these Terms at any time. Material changes will be communicated via email or in-product notification at least 30 days before taking effect.

13. GOVERNING LAW
These Terms shall be governed by and construed in accordance with the laws of the State of Delaware, United States.

14. CONTACT
For questions about these Terms, contact us at legal@governlayer.ai.
"""

PRIVACY_POLICY = """
GovernLayer Privacy Policy
Last Updated: March 16, 2026

1. INTRODUCTION
GovernLayer ("we", "our", "us") is committed to protecting your privacy. This Privacy Policy explains how we collect, use, disclose, and safeguard your information when you use our AI governance platform.

2. INFORMATION WE COLLECT

2.1 Account Information
- Email address (for registration and communication)
- Organization name and details
- API key metadata (creation date, scopes, last used)

2.2 Usage Data
- API request logs (endpoint, timestamp, response time, status code)
- Dashboard access logs
- Feature usage patterns

2.3 Governance Data (submitted by you)
- AI model metadata (names, versions, descriptions)
- Reasoning traces (for drift detection)
- Risk assessment inputs
- Compliance audit parameters
- Agent registry information

2.4 Automatically Collected Data
- IP addresses
- Browser type and version
- Device information
- Cookies and similar technologies

3. HOW WE USE YOUR INFORMATION
- Provide and maintain the Service
- Process governance requests (drift detection, risk scoring, compliance auditing)
- Generate compliance reports and audit trails
- Monitor and enforce rate limits
- Send service notifications and security alerts
- Improve the Service based on usage patterns
- Comply with legal obligations

4. DATA WE DO NOT COLLECT OR USE
- We do NOT use your submitted data to train AI models
- We do NOT sell your personal information to third parties
- We do NOT share your governance data with other customers
- We do NOT access your data without your authorization (except as required by law)

5. DATA STORAGE AND SECURITY
- All data is encrypted in transit (TLS 1.3) and at rest (AES-256)
- Audit records are stored in our immutable SHA-256 hash-chained ledger
- Database access is restricted to authorized personnel only
- We implement security headers (HSTS, CSP, X-Frame-Options)
- Regular security assessments and penetration testing

6. DATA RETENTION
- Account data: Retained while account is active + 90 days after deletion
- API logs: 90 days (configurable for Enterprise plans)
- Audit ledger records: Indefinite (immutable by design)
- Governance data: As configured by your organization
- Waitlist entries: Until converted or manually removed

7. YOUR RIGHTS
You have the right to:
- Access your personal data
- Correct inaccurate data
- Delete your account and associated data
- Export your data (via /v1/enterprise/audit/export)
- Object to processing
- Data portability

To exercise these rights, contact privacy@governlayer.ai.

8. INTERNATIONAL DATA TRANSFERS
If you are located outside the United States, your data may be transferred to and processed in the United States. We implement appropriate safeguards for international transfers.

9. COOKIES
We use essential cookies for authentication and session management. We do not use tracking or advertising cookies.

10. CHILDREN'S PRIVACY
The Service is not intended for use by individuals under 18 years of age. We do not knowingly collect data from children.

11. THIRD-PARTY SERVICES
We use the following third-party services:
- Stripe (payment processing)
- Railway (infrastructure hosting)
- PostgreSQL (database)
- Redis (caching and rate limiting)

Each provider has their own privacy policy governing their data handling.

12. CHANGES TO THIS POLICY
We may update this Privacy Policy from time to time. We will notify you of material changes via email or in-product notification.

13. CONTACT
For privacy-related inquiries:
- Email: privacy@governlayer.ai
- Data Protection: dpo@governlayer.ai

14. DATA PROTECTION OFFICER
For EU/UK data subjects, our Data Protection Officer can be reached at dpo@governlayer.ai.
"""


@router.get("/legal/terms")
def terms_of_service():
    """Terms of Service page."""
    return HTMLResponse(f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Terms of Service — GovernLayer</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Inter',system-ui,sans-serif;background:#08080c;color:#eeeef0;padding:40px 24px;line-height:1.8}}
.container{{max-width:720px;margin:0 auto}}
h1{{font-size:24px;font-weight:800;margin-bottom:8px}}
.meta{{color:#7a7a8e;font-size:13px;margin-bottom:32px}}
pre{{white-space:pre-wrap;font-family:inherit;font-size:14px;color:#b0b0c0;line-height:1.8}}
a{{color:#00ffaa;text-decoration:none}}
.back{{display:inline-block;margin-bottom:24px;color:#7a7a8e;font-size:13px}}
</style></head><body>
<div class="container">
<a href="/" class="back">← Back to GovernLayer</a>
<h1>Terms of Service</h1>
<div class="meta">Last updated: March 16, 2026</div>
<pre>{TERMS_OF_SERVICE.strip()}</pre>
</div></body></html>""")


@router.get("/legal/privacy")
def privacy_policy():
    """Privacy Policy page."""
    return HTMLResponse(f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Privacy Policy — GovernLayer</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Inter',system-ui,sans-serif;background:#08080c;color:#eeeef0;padding:40px 24px;line-height:1.8}}
.container{{max-width:720px;margin:0 auto}}
h1{{font-size:24px;font-weight:800;margin-bottom:8px}}
.meta{{color:#7a7a8e;font-size:13px;margin-bottom:32px}}
pre{{white-space:pre-wrap;font-family:inherit;font-size:14px;color:#b0b0c0;line-height:1.8}}
a{{color:#00ffaa;text-decoration:none}}
.back{{display:inline-block;margin-bottom:24px;color:#7a7a8e;font-size:13px}}
</style></head><body>
<div class="container">
<a href="/" class="back">← Back to GovernLayer</a>
<h1>Privacy Policy</h1>
<div class="meta">Last updated: March 16, 2026</div>
<pre>{PRIVACY_POLICY.strip()}</pre>
</div></body></html>""")


@router.get("/legal/terms.json")
def terms_json():
    """Terms of Service in JSON format (for programmatic access)."""
    return {"document": "Terms of Service", "last_updated": "2026-03-16", "content": TERMS_OF_SERVICE.strip()}


@router.get("/legal/privacy.json")
def privacy_json():
    """Privacy Policy in JSON format (for programmatic access)."""
    return {"document": "Privacy Policy", "last_updated": "2026-03-16", "content": PRIVACY_POLICY.strip()}
