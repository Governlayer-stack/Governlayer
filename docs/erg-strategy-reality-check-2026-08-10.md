# Eval Runtime Governance (ERG) — Reality Check

Honest cross-check of the proposed ERG strategy against what's actually in the codebase today. Every claim in the strategy sits on a spectrum from "already shipped, just re-brand" to "needs 3+ weeks of new work and a real technical decision." Better to know before pitching, not after.

**Verdict up front:** the strategy is directionally right and 3 of the 6 components are already 60–80% built. But the two components you'll get asked hardest about by a lab CTO — **Sandbox Boundary Enforcement** and **Cross-Boundary Attestation** — are the two we'd need genuine new work for. And one of the six (**Behavioral Drift for Specification Gaming**) needs a technical honesty check about what we can actually detect.

---

## Component-by-component reality

### 1. Sandbox Boundary Enforcement · **⚠️ genuinely new work**

**Claim:** "GovernLayer intercepts at the governance layer, not the infrastructure layer. Proxy zero-day doesn't kill the perimeter."

**Reality:** We do not have a boundary today. Everything in `src/` is a decision-layer API. If a lab CTO asks "so where does GovernLayer sit relative to my sandbox network — is it a sidecar, an inline proxy, an SDK the eval harness calls before every action?" — the honest answer is "we're the SDK / API call, we don't own network egress."

**What that means for pitching:**
- Don't claim "we replace the sandbox proxy." We don't.
- Do claim "we're the policy layer on top of your sandbox — the eval harness must call us before any tool invocation, and our policy verdict is what the harness enforces." That's true and defensible.
- The proxy-zero-day story survives if we frame it as "policy stays valid even when the network layer is compromised" — because our decisions are hash-chained separately.

**Work to make it real:** an official **GovernLayer Python SDK** (`governlayer-sdk`) that wraps agent tool calls with a pre-flight `POST /govern` check. ~1 week. This is the artifact a lab CTO wants to see, and it's the smallest lift for the biggest positioning win.

---

### 2. Eval-Specific Egress Policies · **✅ 70% shipped**

**Claim:** "Turn OFF content filters while keeping network/boundary/identity controls STRICTER. Ungoverned model in a maximally governed environment."

**Reality:** The framework rule engine (`src/api/governance.py`) already applies per-use-case policies. Adding a `use_case="evaluation"` mode that flips the severity mapping (content-safety rules downgraded to LOG-ONLY, boundary/identity rules elevated to BLOCKING) is a config change, not new code.

**What we do NOT have today:** per-org "eval mode" toggle with a documented set of which rules invert. The concept works; the ergonomics don't exist.

**Work to make it real:** `POST /v1/policy/mode` endpoint that flips an org into eval-mode with an explicit list of rule overrides, hash-chained onto the ledger as an audit event. Half a week.

---

### 3. Behavioral Drift Detection for Specification Gaming · **⚠️ technical honesty needed**

**Claim:** "Agent hits a block, immediately tries an alternative path to the same target. That pattern triggers a pause and human review."

**Reality:** `src/drift/detection.py` does *semantic* drift against a curated safety manifold via sentence-transformer embeddings. That is NOT the same thing as "detecting an agent trying a second path after a first was blocked."

**The honest technical picture:**
- We can detect **repeated failed tool calls to the same target** — trivial pattern match on `UsageRecord` + `MutationLog`. Already have the raw data.
- We can detect **semantic similarity between a blocked action and a subsequent one** using the existing embedder. Not trivial but plausible.
- We *cannot* detect intent. What we can honestly say is: "we detect the *pattern signature* of specification gaming — retry after block, alternative-path pursuit — and route it for human review before it succeeds."

**What that means for pitching:** don't use the word "detects specification gaming." Use "flags the behavioral pattern that specification gaming produces." That's a defensible technical claim; the first isn't.

**Work to make it real:** new detector in `src/drift/spec_gaming.py` that reads the last N actions per agent from the ledger, embeds them, computes semantic similarity between blocked-then-retried pairs, and fires an escalation if the similarity is above threshold + the retry happened within a short window. ~1 week.

---

### 4. Non-Human Identity Scoping · **✅ 80% shipped**

**Claim:** "Every eval agent gets a unique NHI with zero external permissions, no inherited production credentials, auto-expiring session tokens."

**Reality:** This is *exactly* what we shipped in P1 (commit `7f860dd`). Every `AIAgent` can be issued its own scoped `ApiKey` with `principal_type="agent"`, `expires_in_days` (default 90, can be dropped to 1 for evals), and a scope list. The infrastructure is there.

**What we do NOT have:** an eval-specific credential preset ("issue me an eval credential — 4-hour TTL, `redteam:only` scope, zero prod-access") and the concept of a "prod credential inheritance denial" — right now nothing enforces that an eval NHI can't be granted prod scopes.

**Work to make it real:** `POST /v1/agents/{id}/credentials/eval` convenience endpoint that hard-caps scopes to `redteam,scan` and TTL to 8h max. Plus a validation rule that any credential with `principal_type="eval"` cannot receive `govern` or `audit` scopes. Half a day.

---

### 5. Circuit Breaker · **✅ 90% shipped**

**Claim:** "Four-tier automated response: warn → pause → kill → lockdown."

**Reality:** We already have three of the four. Budget-exhaustion logic (`src/api/agent_registry.py:790-846`) does:
- **pause** → `AgentStatus.SUSPENDED` + `governance_status="suspended"` (line 846)
- **kill** → `AgentStatus.KILLED` + hash-chained termination record (line 791-826)

We do NOT have:
- **warn** as a discrete tier — currently escalation-or-nothing.
- **lockdown** as a distinct state beyond KILLED. In your ERG framing, "lockdown" probably means "kill this agent AND revoke all sibling agents in the same eval batch." Not shipped.

**Work to make it real:** extend `AgentStatus` enum with `WARNED` and `LOCKED_DOWN`. Add a `BatchLockdown` primitive that walks all agents sharing a `batch_id` and kills them atomically. Wire the four tiers as a monotonic escalation ladder in the budget-consume path. ~3 days.

---

### 6. Cross-Boundary Attestation Protocol · **❌ genuinely new work + a strategic question**

**Claim:** "Before any eval touches an external system, both parties sign a bilateral attestation. If every lab uses GovernLayer ERG, cross-boundary incidents become structurally impossible without consent."

**Reality:** Nothing like this exists in the codebase. This is a real protocol design problem, not a coding problem. And the go-to-market claim ("network-effect moat") only works if you can name at least two labs that would commit to the protocol before you build it.

**The strategic honesty:**
- The protocol design itself is 2–3 weeks of careful thinking + a short spec + a reference implementation. Doable.
- The network-effect moat is not something GovernLayer creates alone. Attestation only works when both counterparties use it. You need at least one non-you signatory before the pitch line is defensible.
- Alternative framing that doesn't need the network effect: "the attesting lab has cryptographic proof they told the external system what they were doing, so if the external system objects later, the lab's liability is bounded." This is a unilateral value prop, not bilateral. Much easier to pitch.

**Recommendation:** don't promise cross-boundary attestation in a pitch until you have (a) a signed protocol spec you can hand a lab CTO, and (b) at least one soft LOI from a second signatory. Until then, frame this as a **roadmap item, Q1 2027, contingent on lab-partner interest.** That's honest and it invites the CTO to become the second signatory, which is a much stronger closing motion than "we'll build it and hope."

---

## What a lab CTO will actually ask

Ranked by how sharp the question is and how prepared you need to be:

1. **"Where does GovernLayer sit relative to our existing sandbox proxy — is this a sidecar, an inline gateway, or an SDK we import?"**
   - Right answer: SDK today, inline gateway on the 2027 roadmap. Do not overclaim.

2. **"What's your definition of 'specification gaming' and how do you detect it?"**
   - Right answer: we detect the *behavioral pattern* — repeated attempts at semantically similar goals after a block — not the intent. We escalate to a human, we don't auto-remediate.

3. **"How does this integrate with our existing eval harness — Inspect, OpenAI evals, our custom harness?"**
   - Right answer: we ship a Python SDK. `governlayer.wrap(eval_run)` decorator. First integration is Inspect because it's the industry default.

4. **"You're pre-revenue. Why should we bet our eval infrastructure on you?"**
   - Right answer: pilot fee is refunded if you don't renew. Source is escrowed. Audit ledger is your data, exportable. If we vanish, you inherit the container image and the schema.

5. **"What happens on a boundary-scan attack similar to the OpenAI/HF one?"**
   - Right answer: we log the first probe, escalate on the second, kill on the third. Boundary policy is enforced at the governance layer — a compromise of your proxy doesn't invalidate our policy check because our verdicts are hash-chained independently.

6. **"How do you avoid becoming the compromised proxy yourselves?"**
   - Right answer: we don't proxy tool calls; we return policy verdicts. There's no traffic to intercept. The attack surface is our decision API, which is auth-gated per-org and rate-limited. Even a full compromise of GovernLayer would produce fake verdicts but couldn't exfiltrate your model's outputs — we don't see them.

7. **"What compliance frameworks does ERG map to?"**
   - Right answer: ISO 42001 A.6.2 (evaluation), A.9.4 (testing), EU AI Act Article 9 (risk management for testing), NIST AI RMF MEASURE 2.7 (evaluation practices). Every framework already loaded in the platform.

---

## What's actually shippable, in order of impact-per-hour

If we commit to ERG as a service line, the fastest path to a demonstrable product is:

1. **Eval-mode policy toggle** (component 2) — half a week
2. **Eval-credential preset** (component 4) — half a day
3. **Extended circuit breaker: warn + lockdown tiers** (component 5) — 3 days
4. **Python SDK skeleton** (component 1, honest version) — 1 week
5. **Spec-gaming pattern detector** (component 3, honest version) — 1 week
6. **Attestation protocol spec** (component 6) — 2 weeks including at least one external design review

**Total to a demoable v1 of ERG: ~5 weeks.**

That's a real timeline you can pitch. "ERG launches Q4 2026, pilot slots open now, first three lab partners get co-design input and price lock."

---

## Recommendation

**Do not pitch ERG in its full six-component form yet.** Pitch it as a phased launch:

- **Phase 1 (Q4 2026, live):** Eval-mode policies + eval-credential preset + extended circuit breaker + SDK. All buildable in ~2 weeks. Every claim defensible.
- **Phase 2 (Q1 2027, in progress):** Spec-gaming pattern detection + attestation protocol spec. Frame these as co-design opportunities for early lab partners.

The OpenAI/HuggingFace incident is still your sales trigger — but the honest pitch is "we're the runtime layer that would have caught this, and we're building the eval-specific version of it right now. Do you want to be one of the three labs we co-design phase 2 with?"

That's a stronger close than a full-feature promise you'd have to backpedal on later.

---

## One last thing — the incident citation

The strategy references "the OpenAI/Hugging Face incident" as the sales trigger. Before this goes into any pitch material, I need the source URL. Two reasons:

1. **Accuracy** — misciting a named recent incident to a lab CTO is a credibility killer. If it's a synthesis of several stories, we should say so.
2. **Framing** — the specific technical failure mode matters. If the incident was a proxy-zero-day, our ERG story fits. If it was a training-data leak, or model exfiltration, or a completely different vector, the ERG pitch as written may not be the right frame.

Send the source URL (or "I've been synthesizing across [these three incidents]") and I'll rebuild the pitch on the correct foundation.
