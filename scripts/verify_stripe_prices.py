"""One-off Stripe verification: list products + prices configured in .env."""
import sys

from src.config import get_settings

try:
    import stripe
except ImportError:
    sys.exit("stripe package not installed (try: source venv/bin/activate)")


def fmt_amount(unit_amount: int | None, currency: str) -> str:
    if unit_amount is None:
        return "N/A"
    return f"{currency.upper()} {unit_amount / 100:,.2f}"


def main() -> int:
    s = get_settings()
    if not s.stripe_api_key:
        print("STRIPE_API_KEY is empty in this environment.")
        print("If Stripe is set up only on Railway, this script can't reach it from here.")
        return 2

    stripe.api_key = s.stripe_api_key
    mode = "LIVE" if s.stripe_api_key.startswith("sk_live_") else "TEST"
    print(f"Stripe key: {s.stripe_api_key[:7]}…  ({mode} mode)")
    print()

    expected = {
        "Starter": s.stripe_price_starter,
        "Pro": s.stripe_price_pro,
        "Enterprise": s.stripe_price_enterprise,
    }

    print(f"{'Plan':<12} {'Configured ID':<32} {'Stripe Product':<28} {'Price':<14} {'Interval'}")
    print("-" * 100)
    for plan, price_id in expected.items():
        if not price_id:
            print(f"{plan:<12} (not configured in .env)")
            continue
        try:
            price = stripe.Price.retrieve(price_id, expand=["product"])
            product_name = price.product.name if hasattr(price.product, "name") else str(price.product)
            interval = price.recurring.interval if price.recurring else "one-time"
            print(
                f"{plan:<12} {price_id:<32} {product_name:<28} "
                f"{fmt_amount(price.unit_amount, price.currency):<14} per {interval}"
            )
        except stripe.error.InvalidRequestError as e:
            print(f"{plan:<12} {price_id:<32} ERROR: {e.user_message or e}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
