"""Stripe billing — checkout, webhooks, customer portal, usage summary."""

import logging
from datetime import datetime, timedelta

import stripe
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.config import get_settings
from src.models.database import get_db
from src.models.tenant import ApiKey, Organization, UsageRecord
from src.security.auth import verify_token

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/billing", tags=["billing"])

PLAN_RATE_LIMITS = {"free": 20, "starter": 100, "pro": 500, "enterprise": 2000}


def _get_stripe():
    settings = get_settings()
    if not settings.stripe_api_key:
        raise HTTPException(status_code=503, detail="Stripe not configured")
    stripe.api_key = settings.stripe_api_key
    return stripe


def _get_price_id(plan: str) -> str:
    settings = get_settings()
    prices = {
        "starter": settings.stripe_price_starter,
        "pro": settings.stripe_price_pro,
        "enterprise": settings.stripe_price_enterprise,
    }
    price_id = prices.get(plan)
    if not price_id:
        raise HTTPException(status_code=400, detail=f"No Stripe price configured for plan: {plan}")
    return price_id


# --- Schemas ---

class CheckoutRequest(BaseModel):
    org_slug: str = Field(..., min_length=2)
    plan: str = Field(..., pattern=r"^(starter|pro|enterprise)$")
    success_url: str = Field(default="https://governlayer.ai/billing/success")
    cancel_url: str = Field(default="https://governlayer.ai/billing/cancel")


# --- Endpoints ---

@router.post("/checkout")
def create_checkout(req: CheckoutRequest, email: str = Depends(verify_token),
                    db: Session = Depends(get_db)):
    """Create a Stripe Checkout session for plan upgrade."""
    s = _get_stripe()
    org = db.query(Organization).filter(Organization.slug == req.org_slug).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Create or reuse Stripe customer
    if not org.stripe_customer_id:
        customer = s.Customer.create(
            email=email,
            metadata={"org_slug": org.slug, "org_id": str(org.id)},
        )
        org.stripe_customer_id = customer.id
        db.commit()

    session = s.checkout.Session.create(
        customer=org.stripe_customer_id,
        payment_method_types=["card"],
        line_items=[{"price": _get_price_id(req.plan), "quantity": 1}],
        mode="subscription",
        success_url=req.success_url + "?session_id={CHECKOUT_SESSION_ID}",
        cancel_url=req.cancel_url,
        metadata={"org_slug": org.slug, "plan": req.plan},
    )

    return {"checkout_url": session.url, "session_id": session.id}


@router.post("/webhook")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)):
    """Handle Stripe webhook events. No auth — verified by signature."""
    settings = get_settings()
    if not settings.stripe_webhook_secret:
        raise HTTPException(status_code=503, detail="Webhook secret not configured")

    payload = await request.body()
    sig = request.headers.get("stripe-signature")
    if not sig:
        raise HTTPException(status_code=400, detail="Missing stripe-signature header")

    try:
        event = stripe.Webhook.construct_event(payload, sig, settings.stripe_webhook_secret)
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")

    event_type = event["type"]
    data = event["data"]["object"]

    if event_type == "checkout.session.completed":
        org_slug = data.get("metadata", {}).get("org_slug")
        plan = data.get("metadata", {}).get("plan")
        subscription_id = data.get("subscription")
        if org_slug and plan:
            org = db.query(Organization).filter(Organization.slug == org_slug).first()
            if org:
                org.plan = plan
                org.stripe_subscription_id = subscription_id
                db.commit()
                # Update rate limits on all active API keys
                new_limit = PLAN_RATE_LIMITS.get(plan, 100)
                db.query(ApiKey).filter(
                    ApiKey.org_id == org.id, ApiKey.is_active.is_(True)
                ).update({"rate_limit": new_limit})
                db.commit()
                logger.info("Org %s upgraded to %s", org_slug, plan)

    elif event_type == "customer.subscription.deleted":
        customer_id = data.get("customer")
        if customer_id:
            org = db.query(Organization).filter(
                Organization.stripe_customer_id == customer_id
            ).first()
            if org:
                org.plan = "free"
                org.stripe_subscription_id = None
                db.commit()
                db.query(ApiKey).filter(
                    ApiKey.org_id == org.id, ApiKey.is_active.is_(True)
                ).update({"rate_limit": PLAN_RATE_LIMITS["free"]})
                db.commit()
                logger.info("Org %s downgraded to free (subscription cancelled)", org.slug)

    elif event_type == "invoice.payment_failed":
        customer_id = data.get("customer")
        logger.warning("Payment failed for customer %s", customer_id)

    return {"status": "ok"}


@router.get("/portal/{org_slug}")
def customer_portal(org_slug: str, email: str = Depends(verify_token),
                    db: Session = Depends(get_db)):
    """Create a Stripe Customer Portal session for managing subscription."""
    s = _get_stripe()
    org = db.query(Organization).filter(Organization.slug == org_slug).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    if not org.stripe_customer_id:
        raise HTTPException(status_code=400, detail="No billing account. Create a checkout first.")

    session = s.billing_portal.Session.create(
        customer=org.stripe_customer_id,
        return_url=f"https://governlayer.ai/orgs/{org_slug}",
    )
    return {"portal_url": session.url}


@router.get("/usage/{org_slug}")
def billing_usage(org_slug: str, email: str = Depends(verify_token),
                  db: Session = Depends(get_db)):
    """Get usage summary for current billing month."""
    org = db.query(Organization).filter(Organization.slug == org_slug).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Current month
    now = datetime.utcnow()
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    records = db.query(UsageRecord).filter(
        UsageRecord.org_id == org.id,
        UsageRecord.created_at >= month_start,
    ).all()

    total = len(records)
    by_endpoint: dict[str, int] = {}
    for r in records:
        by_endpoint[r.endpoint] = by_endpoint.get(r.endpoint, 0) + 1

    # Estimate cost based on plan
    plan_prices = {"free": 0, "starter": 49, "pro": 199, "enterprise": 0}

    return {
        "org": org.slug,
        "plan": org.plan,
        "billing_period": f"{month_start.strftime('%Y-%m-%d')} to {now.strftime('%Y-%m-%d')}",
        "total_requests": total,
        "requests_by_endpoint": by_endpoint,
        "plan_cost_usd": plan_prices.get(org.plan, 0),
    }
