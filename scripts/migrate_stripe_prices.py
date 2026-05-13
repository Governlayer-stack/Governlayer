"""Create new Stripe Prices for Starter ($499/mo) and Pro ($1,499/mo).

Idempotent: if a Price already exists for the target product at the target
amount + recurring monthly interval, reuse it instead of creating a duplicate.
Archives the previously-active Prices on the same product so they cannot be
used for new checkouts.

TEST mode only. Aborts if the configured key is sk_live_.
"""

import sys

from src.config import get_settings

try:
    import stripe
except ImportError:
    sys.exit("stripe package not installed (activate venv)")


TARGETS = [
    # (env-var name, plan label, target amount in cents, lookup-key for the Product)
    ("STRIPE_PRICE_STARTER", "Starter", 49900),
    ("STRIPE_PRICE_PRO", "Pro", 149900),
]


def main() -> int:
    s = get_settings()
    if not s.stripe_api_key:
        return _exit("STRIPE_API_KEY is empty in this environment.")
    if not s.stripe_api_key.startswith("sk_test_"):
        return _exit(
            f"Refusing to run: key prefix is '{s.stripe_api_key[:7]}', expected 'sk_test_'.\n"
            "This script is restricted to TEST mode."
        )

    stripe.api_key = s.stripe_api_key
    print("Stripe TEST mode confirmed.\n")

    existing = {
        "Starter": s.stripe_price_starter,
        "Pro": s.stripe_price_pro,
    }

    new_price_ids: dict[str, str] = {}

    for env_var, label, amount_cents in TARGETS:
        print(f"--- {label} → ${amount_cents/100:,.2f}/mo ---")
        old_price_id = existing.get(label)
        if not old_price_id:
            print(f"  (no current {env_var} configured, skipping)")
            continue

        old_price = stripe.Price.retrieve(old_price_id, expand=["product"])
        product = old_price.product
        product_id = product.id if hasattr(product, "id") else product
        product_name = product.name if hasattr(product, "name") else "(unknown)"
        print(f"  Product: {product_name} ({product_id})")
        print(f"  Old Price: {old_price_id} = ${old_price.unit_amount/100:,.2f}/{old_price.recurring.interval}")

        # Look for an existing matching price on this product
        matches = stripe.Price.list(
            product=product_id,
            active=True,
            limit=100,
        )
        match = next(
            (
                p for p in matches.auto_paging_iter()
                if p.unit_amount == amount_cents
                and p.currency == "usd"
                and p.recurring
                and p.recurring.interval == "month"
            ),
            None,
        )

        if match:
            print(f"  Found existing matching Price: {match.id} (reusing — no new Price created)")
            new_price_ids[env_var] = match.id
        else:
            new_price = stripe.Price.create(
                product=product_id,
                unit_amount=amount_cents,
                currency="usd",
                recurring={"interval": "month"},
                nickname=f"{label} — $${amount_cents/100:,.0f}/mo",
            )
            print(f"  Created new Price: {new_price.id} = ${new_price.unit_amount/100:,.2f}/mo")
            new_price_ids[env_var] = new_price.id

        # Archive the old price so it can't be used for new checkouts.
        # If the old price is the product's default_price, swap default first.
        if old_price_id != new_price_ids[env_var]:
            product_obj = stripe.Product.retrieve(product_id)
            if product_obj.default_price == old_price_id:
                stripe.Product.modify(product_id, default_price=new_price_ids[env_var])
                print(f"  Swapped Product default_price → {new_price_ids[env_var]}")
            if old_price.active:
                stripe.Price.modify(old_price_id, active=False)
                print(f"  Archived old Price {old_price_id} (active=false)")
        print()

    if not new_price_ids:
        print("Nothing to update.")
        return 0

    print("=" * 64)
    print("UPDATE THESE RAILWAY ENV VARS:")
    print("=" * 64)
    for env_var, price_id in new_price_ids.items():
        print(f"  {env_var}={price_id}")
    print()
    print("Run on this machine (Railway CLI authenticated):")
    for env_var, price_id in new_price_ids.items():
        print(f"  railway variables --set {env_var}={price_id}")
    print()
    print("Then trigger a Railway redeploy or wait for the service to pick up the new env.")
    return 0


def _exit(msg: str) -> int:
    print(msg, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
