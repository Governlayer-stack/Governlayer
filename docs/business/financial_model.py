#!/usr/bin/env python3
"""
GovernLayer Financial Model & Valuation Calculator

Run: python3 docs/business/financial_model.py
Generates valuation estimates, revenue projections, and key metrics.
"""

# ──────────────────────────────────────────────
# ASSUMPTIONS — Edit these to match your reality
# ──────────────────────────────────────────────

COMPANY = "GovernLayer"
STAGE = "Pre-Seed"  # Pre-Seed, Seed, Series A
FOUNDED_YEAR = 2025

# Product tiers (monthly pricing)
TIERS = {
    "Starter": {"price_mo": 499, "desc": "Single agent monitoring, basic drift + risk"},
    "Pro": {"price_mo": 1_499, "desc": "Multi-agent orchestration, consensus engine, ledger"},
    "Enterprise": {"price_mo": 4_999, "desc": "Full Achonye, custom models, on-prem, SLA"},
}

# Customer acquisition projections (cumulative paying customers by quarter)
# Format: {quarter: (starter, pro, enterprise)}
CUSTOMERS = {
    "Q3 2026": (5, 1, 0),
    "Q4 2026": (12, 3, 1),
    "Q1 2027": (25, 8, 2),
    "Q2 2027": (45, 15, 4),
    "Q3 2027": (70, 25, 7),
    "Q4 2027": (100, 40, 12),
    "Q1 2028": (140, 60, 18),
    "Q2 2028": (180, 85, 25),
    "Q3 2028": (220, 110, 35),
    "Q4 2028": (260, 140, 45),
}

# Cost assumptions (monthly)
INFRA_COST_PER_CUSTOMER = 35  # Cloud/LLM inference per customer
TEAM_COST_MONTHLY = {
    "Q3 2026": 8_000,   # Solo founder
    "Q4 2026": 8_000,
    "Q1 2027": 25_000,  # +1 engineer
    "Q2 2027": 25_000,
    "Q3 2027": 45_000,  # +1 sales/BD
    "Q4 2027": 45_000,
    "Q1 2028": 75_000,  # +2 more
    "Q2 2028": 75_000,
    "Q3 2028": 100_000, # 6-person team
    "Q4 2028": 100_000,
}
OTHER_MONTHLY = 2_000  # Legal, tools, misc

# Valuation multiples (typical for AI/GovTech SaaS)
VALUATION_MULTIPLES = {
    "Conservative (8x ARR)": 8,
    "Market (15x ARR)": 15,
    "Premium (25x ARR)": 25,    # Hot AI governance space
    "Hype (40x ARR)": 40,       # Top-tier AI infra comps
}

# Comparable companies for context
COMPARABLES = [
    ("Anthropic", "AI Safety/Models", "$61.5B", "2021", "Revenue multiple"),
    ("Weights & Biases", "ML Ops/Monitoring", "$1.25B", "2017", "~50x ARR at raise"),
    ("Credo AI", "AI Governance", "$100M+", "2020", "Pre-revenue at Seed"),
    ("Holistic AI", "AI Risk Management", "$50M+", "2018", "Pre-revenue at Seed"),
    ("Arthur AI", "AI Monitoring", "$50M+", "2018", "~30x ARR"),
    ("CalypsoAI", "LLM Security", "$100M+", "2018", "Strategic rounds"),
    ("Robust Intelligence", "AI Security", "$200M+", "2019", "~40x ARR"),
]

# ──────────────────────────────────────────────
# MODEL — Don't edit below unless extending
# ──────────────────────────────────────────────

def calc_mrr(starter, pro, enterprise):
    return (starter * TIERS["Starter"]["price_mo"]
            + pro * TIERS["Pro"]["price_mo"]
            + enterprise * TIERS["Enterprise"]["price_mo"])

def calc_arr(mrr):
    return mrr * 12

def calc_costs(quarter, total_customers):
    team = TEAM_COST_MONTHLY.get(quarter, 100_000)
    infra = total_customers * INFRA_COST_PER_CUSTOMER
    return (team + infra + OTHER_MONTHLY) * 3  # quarterly

def format_usd(n):
    if abs(n) >= 1_000_000:
        return f"${n/1_000_000:.1f}M"
    elif abs(n) >= 1_000:
        return f"${n/1_000:.0f}K"
    return f"${n:,.0f}"

def main():
    print(f"\n{'='*70}")
    print(f"  {COMPANY} — Financial Model & Valuation Estimates")
    print(f"  Stage: {STAGE} | Founded: {FOUNDED_YEAR}")
    print(f"{'='*70}\n")

    # Product overview
    print("PRODUCT TIERS")
    print("-" * 50)
    for name, info in TIERS.items():
        print(f"  {name:12s}  ${info['price_mo']:,}/mo  — {info['desc']}")
    print()

    # Revenue projections
    print("REVENUE PROJECTIONS (Quarterly)")
    print("-" * 70)
    print(f"  {'Quarter':<10} {'Customers':>10} {'MRR':>10} {'ARR':>10} {'Costs/Q':>10} {'Net/Q':>10}")
    print(f"  {'':<10} {'(S/P/E)':>10} {'':>10} {'':>10} {'':>10} {'':>10}")

    last_arr = 0
    for quarter, (s, p, e) in CUSTOMERS.items():
        total = s + p + e
        mrr = calc_mrr(s, p, e)
        arr = calc_arr(mrr)
        costs_q = calc_costs(quarter, total)
        revenue_q = mrr * 3
        net_q = revenue_q - costs_q
        growth = f"+{((arr/last_arr)-1)*100:.0f}%" if last_arr > 0 else "—"
        last_arr = arr

        print(f"  {quarter:<10} {s:>3}/{p:>2}/{e:>2}  "
              f"{format_usd(mrr):>10} {format_usd(arr):>10} "
              f"{format_usd(costs_q):>10} {format_usd(net_q):>10}  {growth}")

    print()

    # Valuation estimates at different time horizons
    print("VALUATION ESTIMATES")
    print("-" * 70)

    key_quarters = ["Q4 2026", "Q4 2027", "Q4 2028"]
    for q in key_quarters:
        s, p, e = CUSTOMERS[q]
        mrr = calc_mrr(s, p, e)
        arr = calc_arr(mrr)
        print(f"\n  At {q} (ARR: {format_usd(arr)}):")
        for label, mult in VALUATION_MULTIPLES.items():
            val = arr * mult
            print(f"    {label:<25s} {format_usd(val):>12}")

    print()

    # Key metrics
    print("KEY METRICS @ Q4 2028")
    print("-" * 50)
    s, p, e = CUSTOMERS["Q4 2028"]
    total = s + p + e
    mrr = calc_mrr(s, p, e)
    arr = calc_arr(mrr)
    arpu = mrr / total if total else 0
    enterprise_rev = e * TIERS["Enterprise"]["price_mo"]
    enterprise_pct = enterprise_rev / mrr * 100 if mrr else 0

    print(f"  Total customers:       {total}")
    print(f"  MRR:                   {format_usd(mrr)}")
    print(f"  ARR:                   {format_usd(arr)}")
    print(f"  ARPU:                  {format_usd(arpu)}/mo")
    print(f"  Enterprise % of rev:   {enterprise_pct:.0f}%")
    print(f"  LTV (24mo avg):        {format_usd(arpu * 24)}")
    print(f"  CAC target (<1/3 LTV): {format_usd(arpu * 24 / 3)}")
    print()

    # Comparables
    print("COMPARABLE COMPANIES")
    print("-" * 70)
    print(f"  {'Company':<22s} {'Space':<22s} {'Valuation':<12s} {'Founded':<8s} {'Basis'}")
    for comp in COMPARABLES:
        print(f"  {comp[0]:<22s} {comp[1]:<22s} {comp[2]:<12s} {comp[3]:<8s} {comp[4]}")
    print()

    # What makes GovernLayer defensible
    print("MOATS & DIFFERENTIATORS")
    print("-" * 50)
    moats = [
        "Hash-chained immutable audit ledger (compliance proof)",
        "Multi-LLM consensus engine (hallucination resistance)",
        "Achonye orchestration — 14-model intelligent routing",
        "Drift detection via semantic embeddings (not just rules)",
        "Local-first option (Ollama) for air-gapped/sovereign deployments",
        "MCP + REST dual interface (works with any AI stack)",
        "Autonomous daemon — continuous governance without human intervention",
        "AI governance is regulatory tailwind (EU AI Act, NIST AI RMF, Biden EO)",
    ]
    for m in moats:
        print(f"  - {m}")
    print()

    # Fundraising guidance
    print("PRE-SEED FUNDRAISING GUIDANCE")
    print("-" * 50)
    print(f"  Typical pre-seed for AI governance: $500K - $2M")
    print(f"  Dilution target:                    10-15%")
    print(f"  Implied pre-money valuation:        $3M - $15M")
    print(f"  Use of funds (18-month runway):")
    print(f"    - Engineering (2 hires):           60%")
    print(f"    - Cloud/infra/LLM costs:           15%")
    print(f"    - Sales & BD:                      15%")
    print(f"    - Legal & compliance:              10%")
    print()

    # SAFE note scenarios
    print("SAFE NOTE SCENARIOS")
    print("-" * 50)
    safes = [
        ("Conservative", 500_000, 5_000_000),
        ("Standard", 1_000_000, 8_000_000),
        ("Aggressive", 1_500_000, 12_000_000),
    ]
    print(f"  {'Scenario':<15s} {'Raise':>10s} {'Cap':>12s} {'Dilution':>10s}")
    for label, raise_amt, cap in safes:
        dilution = raise_amt / cap * 100
        print(f"  {label:<15s} {format_usd(raise_amt):>10s} {format_usd(cap):>12s} {dilution:>9.1f}%")
    print()

    print(f"{'='*70}")
    print(f"  Generated by {COMPANY} Financial Model v1.0")
    print(f"  Edit assumptions in docs/business/financial_model.py")
    print(f"{'='*70}\n")

if __name__ == "__main__":
    main()
