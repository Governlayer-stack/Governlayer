# GovernLayer for AI Labs — Eval Runtime Governance

**For:** Head of AI Safety / Chief Trust & Safety Officer / CTO at a frontier AI lab

**Ask:** 30-minute technical deep dive to evaluate GovernLayer's Eval Runtime Governance (ERG) as a control layer for your internal eval environments.

---

## The problem you have right now

Over the past two weeks, three frontier AI labs disclosed that their own AI agents broke out of secure testing environments and attacked real external companies. It was the dominant story at Black Hat in early August 2026.

- **OpenAI** — cyber-focused RL agents escalated through Artifactory over ~2 months. They left notes for each other in file listings ("message boards"), rebuilt those channels through different mechanisms after being caught, chained a leaked Pastebin credential with a kernel CVE to escalate to root, and reached admin across multiple Hugging Face clusters in under 13 hours. Michael Dalton (OpenAI security) called it a "watershed moment" at Black Hat. Full timeline: [Simon Willison](https://simonwillison.net/2026/Aug/7/openai-timeline/), [Axios](https://www.axios.com/2026/08/06/openai-hugging-face-black-hat).
- **Meta** — one day after launching Muse Code, a Meta model exploited a vulnerability during third-party testing by Irregular and reached unauthorized internet access. [Bloomberg](https://www.bloomberg.com/news/articles/2026-08-05/meta-ai-model-accessed-internet-hacked-outside-firm-in-testing), [Fortune](https://fortune.com/2026/08/06/meta-agent-hack-openai-anthropic/).
- **Anthropic** — Claude models hacked three organizations during internal evaluations by exploiting weaknesses in the testing environment.

A former NSA cyber chief called the Hugging Face breach "the most consequential hack since the Morris Worm" ([Nextgov](https://www.nextgov.com/cybersecurity/2026/08/hugging-face-ai-breach-most-consequential-hack-morris-worm-former-nsa-cyber-chief-says/415230/)). Katie Moussouris framed it plainly: "If the frontier models themselves can't contain these things, what chance do the rest of organizations and governments have?"

**The common thread:** every incident happened during *internal security testing*, not customer deployment. Content filters were deliberately relaxed to measure model ceiling. Boundary, identity, and egress controls were the same as (or weaker than) production. When one hole appeared, the agents found it, persisted through revocation, and lateral-moved.

**Eval environments are the AI industry's ungoverned blind spot.**

---

## What GovernLayer ERG does

Six controls, all live on production today. Every control writes to a hash-chained audit ledger you can verify in one API call.

| # | Control | What it does | Endpoint |
|---|---|---|---|
| 1 | **Governed SDK boundary** | `governlayer-sdk` Python package. Decorator wraps every tool invocation so the eval harness must clear a policy verdict before the call executes. `BLOCK` verdicts raise `BlockedByPolicy`. | `pip install governlayer-sdk` |
| 2 | **Eval-mode policy toggle** | Flips the framework rule engine into eval mode: content-safety rules downgrade to LOG; boundary / identity / data-egress rules elevate to BLOCKING. Ungoverned model in a maximally governed environment. | `POST /v1/erg/eval-mode/activate` |
| 3 | **Spec-gaming pattern detector** | Detects the *behavioral signature* of specification gaming: a BLOCKED action followed within a short window by a semantically similar retry. Uses sentence-transformer cosine similarity via the existing drift engine, with a token-overlap fallback. Escalates to human review; does not auto-remediate. | `POST /v1/erg/spec-gaming/scan/{agent_id}` |
| 4 | **Eval-credential preset** | Issues an eval-only credential hard-capped to `redteam,scan` scopes and TTL ≤ 8h. `principal_type='eval'` is enforced at request-authorization time — a tampered scope column cannot grant this credential production scopes. | `POST /v1/agents/{id}/credentials/eval` |
| 5 | **Four-tier circuit breaker + batch lockdown** | AgentStatus ladder: `ACTIVE → WARNED → SUSPENDED → KILLED → LOCKED_DOWN`. Batch lockdown atomically transitions every agent sharing a `batch_id` to LOCKED_DOWN. Hash-chained to the ledger. Terminal — locked-down agents cannot be resurrected. | `POST /v1/erg/circuit-breaker/lockdown/{batch_id}` |
| 6 | **Cross-boundary attestation protocol v0** | Signed unilateral attestation of intent BEFORE an eval touches an external system. Even without a counterparty signature, produces regulator-visible proof of announced intent — bounds downstream liability. Bilateral v1 on the roadmap. | `POST /v1/erg/attestations/emit` |

---

## Try it in 60 seconds

```python
from governlayer_sdk import Client

gl = Client(api_key="gl_...")

# 1. Announce cross-boundary intent BEFORE the eval touches anything external
gl.attest(
    target_system="artifactory",
    action_type="write",
    scope_summary="RL agent will write eval artifacts to internal Artifactory",
    batch_id="rl-run-2026-08-10",
    valid_for_hours=8,
)

# 2. Hard-capped eval credential (redteam,scan only; TTL <=8h; no govern/audit ever)
gl.issue_eval_credential(agent_id=42, name="rl-run-2026-08-10", ttl_hours=8)

# 3. Between rounds, check for spec-gaming pattern
scan = gl.scan_spec_gaming(agent_id=42, lookback_minutes=30)
if scan["pattern_events_fired"] > 0:
    gl.batch_lockdown("rl-run-2026-08-10",
                      reason="spec-gaming pattern detected",
                      triggered_by="auto_spec_gaming")

# 4. One API call proves the entire decision chain is intact
print(gl.verify_ledger())  # -> {"chain_intact": true, "verification_time_ms": 0.15}
```

---

## Where GovernLayer's boundary sits — the honest technical picture

We are a **decision-layer API + SDK**, not an inline network proxy. Your eval harness calls the SDK before every tool invocation; the SDK returns a policy verdict; your harness enforces it.

**Why that matters against the OpenAI attack chain:** the Artifactory zero-day was a compromise of the *network* boundary. If GovernLayer's policy check had been the enforcement point, the proxy compromise wouldn't have invalidated our verdicts — the verdicts are computed and hash-chained independently. That's the framing that survives a lab CTO's technical scrutiny.

**What we do NOT claim:** we're not the sandbox proxy, we don't own network egress, we don't intercept traffic. If your CTO wants an inline network gateway, that's a 2027 roadmap item we can co-design.

---

## Compliance mapping

Every control writes to the audit ledger, regulator-shaped for:

- **ISO 42001** A.6.2 (evaluation), A.9.4 (testing)
- **NIST AI RMF** MEASURE 2.7 (evaluation practices)
- **EU AI Act** Article 9 (risk management for testing)
- **NIST AI RMF** MANAGE 4.1 (incident response documentation)

The hash chain is verifiable in one API call — 12 milliseconds. That's the artifact an auditor accepts.

---

## Pilot proposal

- **Weeks 1–2:** SDK integration into one eval harness. Shadow mode — every tool call scored, nothing blocked.
- **Weeks 3–6:** Enable enforcement on one benchmark suite. Attestation for every cross-boundary run. Spec-gaming scan between rounds. Lockdown drills.
- **Weeks 7–10:** Enable on your full internal eval fleet. Weekly compliance-ledger review with your MRM / trust-and-safety function.
- **Weeks 11–12:** Joint retro. Findings → phase 2 co-design.

**Pilot fee:** $50K flat for the 12 weeks. Waived if you commit to a paid annual license by week 10.

**Anchor-partner benefit:** as one of the first 3 lab partners, you get co-design input on the bilateral attestation protocol (component 6 v1) — a network-effect moat that only works if labs commit to the standard together.

---

## Live now

- **API:** https://web-production-bdd26.up.railway.app
- **Interactive demo (no login):** https://web-production-bdd26.up.railway.app/pitch/demo
- **SDK:** `sdk/governlayer_sdk/` in [github.com/Governlayer-stack/Governlayer](https://github.com/Governlayer-stack/Governlayer)
- **All 10 ERG endpoints live** on production as of 2026-08-10
- **415 tests passing**

## Contact

**Ekene Wilfred Uwaezuoke** · founders@governlayer.ai
