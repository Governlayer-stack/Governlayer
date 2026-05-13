#!/usr/bin/env python3
"""
GovernLayer Cost Model
=======================

Computes per-decision inference cost for the GovernLayer (Achonye) tiered
routing approach vs. a single-frontier-model baseline. Produces the math
behind the pitch deck claim of "70% lower inference cost".

Run:
    python scripts/cost_model.py
    python scripts/cost_model.py --local 0.7 --single 0.25 --consensus 0.05
    python scripts/cost_model.py --baseline claude-sonnet
    python scripts/cost_model.py --in-tokens 1200 --out-tokens 600

Pure stdlib. No external deps.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Pricing table (USD per 1,000 tokens)
# Sourced May 2026 — see docs/COST_MODEL.md for citations.
# Pricing pages express $/1M tokens; we divide by 1000 for $/1k tokens.
# ---------------------------------------------------------------------------

PRICES_PER_1K = {
    # OpenAI — developers.openai.com/api/docs/pricing
    "gpt-4o":        {"in": 0.00250, "out": 0.01000},  # $2.50 / $10.00 per 1M
    "gpt-4o-mini":   {"in": 0.00015, "out": 0.00060},  # $0.15 / $0.60  per 1M

    # Anthropic — platform.claude.com/docs/en/about-claude/pricing
    "claude-sonnet": {"in": 0.00300, "out": 0.01500},  # $3.00 / $15.00 per 1M (Sonnet 4.6)
    "claude-haiku":  {"in": 0.00100, "out": 0.00500},  # $1.00 / $5.00  per 1M (Haiku 4.5)
    "claude-opus":   {"in": 0.00500, "out": 0.02500},  # $5.00 / $25.00 per 1M (Opus 4.7)

    # Google — ai.google.dev/gemini-api/docs/pricing
    "gemini-2.5-pro":{"in": 0.00125, "out": 0.01000},  # $1.25 / $10.00 per 1M (≤200k ctx)

    # Local (Ollama on owned hardware) — amortized at zero marginal $/call.
    # Real cost = electricity + hardware amortization, immaterial per call.
    "ollama-local":  {"in": 0.00000, "out": 0.00000},
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TierCost:
    name: str
    distribution: float       # 0..1
    cost_per_decision: float  # USD
    justification: str


def cost_per_decision(model: str, in_tokens: int, out_tokens: int) -> float:
    """Cost in USD for one decision against `model` at given token counts."""
    p = PRICES_PER_1K[model]
    return (in_tokens / 1000.0) * p["in"] + (out_tokens / 1000.0) * p["out"]


def consensus_cost(models: list[str], in_tokens: int, out_tokens: int) -> float:
    """
    Multi-model consensus cost: every model in `models` is called once with
    the same prompt (independent inference, no shared cache assumed).
    """
    return sum(cost_per_decision(m, in_tokens, out_tokens) for m in models)


# ---------------------------------------------------------------------------
# Main calculation
# ---------------------------------------------------------------------------

def compute(
    pct_local: float,
    pct_single: float,
    pct_consensus: float,
    in_tokens: int,
    out_tokens: int,
    baseline_model: str,
    single_model: str,
    consensus_models: list[str],
) -> dict:
    """Returns the full cost breakdown."""
    # Validate distribution
    total = pct_local + pct_single + pct_consensus
    if abs(total - 1.0) > 1e-6:
        raise ValueError(
            f"Routing distribution must sum to 1.0, got {total:.4f} "
            f"(local={pct_local}, single={pct_single}, consensus={pct_consensus})"
        )

    # Per-tier per-decision cost
    local_cost     = cost_per_decision("ollama-local", in_tokens, out_tokens)
    single_cost    = cost_per_decision(single_model, in_tokens, out_tokens)
    consensus_cst  = consensus_cost(consensus_models, in_tokens, out_tokens)

    # Blended Achonye cost
    achonye_cost = (
        pct_local     * local_cost     +
        pct_single    * single_cost    +
        pct_consensus * consensus_cst
    )

    # Baseline: 100% on frontier model
    baseline_cost = cost_per_decision(baseline_model, in_tokens, out_tokens)

    savings_per_decision = baseline_cost - achonye_cost
    savings_pct          = (savings_per_decision / baseline_cost) * 100.0

    tiers = [
        TierCost(
            name="Local (Ollama)",
            distribution=pct_local,
            cost_per_decision=local_cost,
            justification="Self-hosted, zero marginal per-call cost",
        ),
        TierCost(
            name="Single frontier",
            distribution=pct_single,
            cost_per_decision=single_cost,
            justification=f"{single_model} @ "
                          f"${PRICES_PER_1K[single_model]['in']*1000:.2f} in / "
                          f"${PRICES_PER_1K[single_model]['out']*1000:.2f} out per 1M",
        ),
        TierCost(
            name="Multi-model",
            distribution=pct_consensus,
            cost_per_decision=consensus_cst,
            justification=f"{len(consensus_models)}-model consensus: "
                          f"{', '.join(consensus_models)}",
        ),
    ]

    return {
        "tiers": tiers,
        "baseline_model": baseline_model,
        "baseline_cost": baseline_cost,
        "achonye_cost": achonye_cost,
        "savings_per_decision": savings_per_decision,
        "savings_pct": savings_pct,
        "in_tokens": in_tokens,
        "out_tokens": out_tokens,
    }


# ---------------------------------------------------------------------------
# Pretty-print
# ---------------------------------------------------------------------------

def fmt_usd(x: float, places: int = 4) -> str:
    return f"${x:,.{places}f}"


def print_report(result: dict) -> None:
    in_tok = result["in_tokens"]
    out_tok = result["out_tokens"]
    baseline = result["baseline_model"]
    b_price = PRICES_PER_1K[baseline]

    print(
        f"\nGovernLayer Cost Model — May 2026 prices, "
        f"{in_tok} in / {out_tok} out tokens per decision"
    )
    print("=" * 78)

    # Tier table
    print(f"\n{'Tier':<20} {'Distribution':<14} {'$/decision':<14} Justification")
    print("─" * 78)
    for t in result["tiers"]:
        print(
            f"{t.name:<20} "
            f"{t.distribution*100:>5.1f}%{'':<8}"
            f"{fmt_usd(t.cost_per_decision):<14} "
            f"{t.justification}"
        )

    # Summary
    print()
    print(
        f"Baseline:  100% {baseline} "
        f"(${b_price['in']*1000:.2f} in / ${b_price['out']*1000:.2f} out per 1M)"
        f"   →  {fmt_usd(result['baseline_cost'])} / decision"
    )
    print(
        f"Achonye:   weighted blend"
        f"{'':>34}→  {fmt_usd(result['achonye_cost'])} / decision"
    )
    print()
    print(
        f"Savings: {fmt_usd(result['savings_per_decision'])} / decision  "
        f"=  {result['savings_pct']:.1f}% lower than baseline"
    )

    # Annualized
    print()
    print("Annualized projections")
    print("─" * 78)
    for volume in (100_000, 1_000_000, 10_000_000):
        saved = result["savings_per_decision"] * volume
        baseline_total = result["baseline_cost"] * volume
        achonye_total = result["achonye_cost"] * volume
        print(
            f"  {volume:>12,} decisions/year:  "
            f"baseline {fmt_usd(baseline_total, 0):>12}  "
            f"achonye {fmt_usd(achonye_total, 0):>10}  "
            f"saved {fmt_usd(saved, 0):>10}"
        )

    # Deck check
    print()
    print("Pitch deck claim check")
    print("─" * 78)
    deck_claim = 70.0
    actual = result["savings_pct"]
    diff = actual - deck_claim
    if diff >= 0:
        print(
            f"  Deck claims 70% savings. Bottom-up math gives {actual:.1f}%. "
            f"Deck claim is DEFENSIBLE (+{diff:.1f} pp margin)."
        )
    else:
        print(
            f"  Deck claims 70% savings. Bottom-up math gives {actual:.1f}%. "
            f"Deck claim is OPTIMISTIC by {-diff:.1f} pp. Consider revising."
        )
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="GovernLayer per-decision cost model.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--local",     type=float, default=0.80,
                   help="Fraction of decisions routed to local Ollama (0..1).")
    p.add_argument("--single",    type=float, default=0.18,
                   help="Fraction routed to a single frontier model (0..1).")
    p.add_argument("--consensus", type=float, default=0.02,
                   help="Fraction routed to multi-model consensus (0..1).")
    p.add_argument("--in-tokens",  type=int, default=800,
                   help="Average input tokens per governance decision.")
    p.add_argument("--out-tokens", type=int, default=400,
                   help="Average output tokens per governance decision.")
    p.add_argument("--baseline", default="gpt-4o",
                   choices=sorted(PRICES_PER_1K.keys()),
                   help="Single-frontier-model baseline for comparison.")
    p.add_argument("--single-model", default="gpt-4o-mini",
                   choices=sorted(PRICES_PER_1K.keys()),
                   help="Model used in the 'single frontier' Achonye tier.")
    p.add_argument("--consensus-models", nargs="+",
                   default=["gpt-4o", "claude-sonnet", "gemini-2.5-pro"],
                   help="Models used in the consensus tier (space-separated).")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = compute(
            pct_local=args.local,
            pct_single=args.single,
            pct_consensus=args.consensus,
            in_tokens=args.in_tokens,
            out_tokens=args.out_tokens,
            baseline_model=args.baseline,
            single_model=args.single_model,
            consensus_models=args.consensus_models,
        )
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print_report(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
