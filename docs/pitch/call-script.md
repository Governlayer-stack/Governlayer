# GovernLayer — Investor Call Script

**Live deck:** https://www.governlayer.ai/pitch/094dc661d9f6ce054a17bec4
**Round:** $1M pre-seed at $5M post-money SAFE.
**Founder line:** Ekene Wilfred Uwaezuoke — founders@governlayer.ai

---

## OPEN — first 90 seconds (do not skip)

> "Thanks for making time. Before I run the deck I want to acknowledge two things up front, because they tell you how I work.
>
> First — the EU AI Act Digital Omnibus reached political agreement on May 6 and was confirmed by the Council on May 13. That moved Annex III high-risk obligations to December 2027 and Annex I to August 2028. I updated the deck this week to reflect that. The version you're looking at is current as of [today's date].
>
> Second — that deferral is a buying-window extension, not a thesis change. NYC LL144 is enforcing today. Colorado SB 205 went effective in February. OMB M-24-10 is live for federal contractors. ISO 42001 is being written into Fortune 500 RFPs regardless of Brussels timing. Procurement cycles are 6 to 18 months — serious buyers start preparing now.
>
> That's the context. Let me show you the product."

**Why this open works:** Pre-empts the single sharpest critique a domain investor will land. Demonstrates you track your own regulatory space in real time. Reframes a credibility liability into a credibility asset. Buys you the rest of the meeting.

---

## SLIDE-BY-SLIDE NOTES (one line each)

| # | Slide | What to say |
|---|---|---|
| 1 | Title | "Runtime AI governance for the agentic era. Live product, $1M round, $5M cap." |
| 2 | Problem | "73% of enterprises have no automated AI governance. When an agent makes a decision, no one can prove what happened. Replit wiped a prod DB and fabricated a cover story — that's the kind of incident we exist to make impossible." |
| 3 | Why Now | **Read the open above. Then walk the timeline.** "US enforcement live today. EU deferred but still arriving — and outside counsel is telling regulated clients to keep preparing." |
| 4 | Solution | "Three primitives: continuous drift detection, multi-LLM consensus on critical decisions, and a tamper-evident audit ledger. Hash-chained provenance — the audit artifact financial regulators already accept, applied to AI." |
| 5 | Product | "Live at governlayer.ai/workspace. 17 services, 100+ endpoints. Depth-first: full control mapping for NYC LL144, OMB M-24-10, Colorado SB 205. Breadth across 29 frameworks." |
| 6 | Market | "TAM $3.8B — Gartner AI TRiSM plus adjacent GRC and model-risk budgets, because that's where procurement actually pulls the money from. SAM $650M–$1.1B US regulated mid-large. SOM $25–75M ARR over three years." |
| 7 | Traction | "Built, shipped, live. Production platform on Railway, Stripe billing wired, pilots in conversation across banking, healthcare, federal." |
| 8 | Business Model | "Land at $499–$1,499/mo, expand to enterprise. Unit economics are **modeled** — replaced by actuals after first 10 paying customers. 2.5x to 5.75x LTV:CAC range tested at 2- and 4-year retention." |
| 9 | Competition | "Two close comps — CalypsoAI and Lakera — were acquired in 2025 for $180M and ~$300M. Category is M&A-active. We're the only one with all four: runtime enforcement, tamper-evident ledger, multi-LLM routing, and regulatory depth." |
| 10 | Team | "Senior Engineering Program Manager at Google — I support AI governance, risk, and compliance programs across multiple AI product surfaces. Former Deloitte. ISO 42001 Lead Implementer. Patent filed March 10. Round is structured so 45% goes to engineering — that retires the bus-factor concern." |
| 11 | Ask | "$1M at $5M cap. 45% engineering / 30% sales / 15% ops / 10% infra. Q2 GA, Q3 SOC 2 Type II + SSO + on-prem, Q4 $500K ARR. Series A in 2027 at $2–5M ARR." |

---

## THE BANKING WEDGE — use when the room is a fintech/financial-services investor

Two vertical use cases GovernLayer ships today. Both live at endpoints you can hit right now. Both write to the same hash-chained audit ledger the rest of the platform uses.

### 1. AI Credit Underwriting Oversight — fair lending + adverse action

> "We sit between the bank's credit-decisioning AI and the final decision. Every denial flows through us. We generate the ECOA-compliant adverse-action reasons the applicant is legally entitled to under Reg B — pulled from the Appendix C statutory catalog, not free text. We flag any protected-class proxy contribution — ZIP code, surname, census tract — and block the notice from going out until fair-lending review clears it. Borderline denials (model confidence under 85%) escalate to a Compliance Officer with a 4-hour SLA. And there's a `/credit/sr26-2/{system_name}` endpoint that emits the model risk management document under **SR 26-2 and OCC Bulletin 2026-13** — the guidance that replaced SR 11-7 in April 2026 and extended MRM to AI/ML systems including agentic ones. When the CFPB or OCC asks the bank *'how do you oversee this model?'* — one URL, one document."

**Endpoints:** `POST /credit/oversight`, `GET /credit/reason-codes`, `GET /credit/sr26-2/{system_name}` *(the `/credit/sr11-7/{system_name}` alias remains, with an RFC 8594 Deprecation header, so any pre-April-2026 integrations keep working through end of year.)*
**Value line:** Fair lending exam readiness. SR 26-2 / OCC 2026-13 model risk documentation. Defensible AI decisions.
**Market pull:** Wolters Kluwer's June 2026 survey found ~3-in-4 US banks lack documented rollback / routing / reporting capability — the exact stack we ship.

### 2. Fraud & AML Decision Escalation — false-positive protection

> "When the bank's fraud AI wants to freeze an account or block a transaction on what's actually a legitimate customer, we intercept. Low-confidence actions, repeat-action patterns on the same customer, and specific AML typologies — sanctions hit, PEP, elder financial abuse, human trafficking — always route to an analyst before the customer is harmed. UDAAP queue for consumer-harm risk, BSA/AML queue for sanctions and typology-driven actions. Every review is stamped into the same ledger — which is exactly the *documented human-in-the-loop record* a BSA/AML exam wants to see."

**Endpoints:** `POST /fraud/escalation` (routes to `BSA_AML` and/or `UDAAP` HITL queues)
**Value line:** Fewer UDAAP complaints. Lower customer attrition from wrongful freezes. Documented HITL for BSA/AML audits.

**How to close the banking segment:**

> "If you're evaluating a design partner in this space — Prairie First, Cross River, a mid-tier community bank — I can wire this into their pilot in under two weeks. The platform is live; these two flows are shipping this sprint. What I need from a design partner is the feature-attribution schema their decisioning model already produces. Everything else is our lift."

### The banking-comp cheat sheet (2025-2026, verified)

If a sharp fintech investor names any of these, be ready:

| Comp | What they actually are today | The right frame |
|---|---|---|
| **Zest AI** ([zest.ai](https://www.zest.ai)) | End-to-end AI underwriting *platform* — they replace the credit model. Credit-union channel (SchoolsFirst, Members 1st, ORNL, Truliant). Citi Ventures on cap table. Customer-led round Nov 2025. Generates adverse-action codes. | "Zest **replaces** the model. We sit **between** any model and the decision — vendor-neutral. We work with Zest, FICO, or in-house. Zest customers are our buyers, not our targets." |
| **FairPlay AI** ([fairplay.ai](https://fairplay.ai)) | Fair-lending narrative locked in. $10M Feb 2025 from JPMorgan Chase + Nyca + Infinity ($24.5M total). Wolters Kluwer distribution deal Feb 2025. Named customers: Varo, Figure, Octane. 25 banks/fintechs claimed. Post-hoc "Second Look" fairness analysis. | "FairPlay does post-hoc fairness analysis on the model's output. We intercept the live action, generate the statutory reasons, and route to a named human role with a regulator-defensible SLA clock. Different point in the decision loop." |
| **Trustible** ([trustible.ai](https://trustible.ai)) | Generalist AI governance. $4.6M seed June 2025. No bank customers named (logos: Leidos, Nuix, Fortune 500 CPG). Gartner Honorable Mention 2026. SR 26-2 is one framework of many, not the wedge. | Name-check and move on. "Analyst credibility but not banking-native." |
| **Fiddler AI** ([fiddler.ai](https://fiddler.ai)) | Pivoted to "AI Control Plane for Enterprise Agents." $30M Series C Jan 2026. Bias monitoring, drift, lending page — but **does not generate adverse-action reason codes**. Observability, not decision-loop intervention. | "Fiddler is observability. We're enforcement. Adjacent categories, adjacent buyers." |
| **Sei AI** ([seiright.com](https://www.seiright.com)) | New entrant. Publishing detailed ECOA Reg B adverse-action playbooks. Direct wedge competitor to watch. | "On our monitoring list. Content-first, product state unclear." |

### The regulatory tailwind that closes the story

- **SR 11-7 rescinded April 17, 2026** — replaced by **SR 26-2** (Fed) + **OCC Bulletin 2026-13**. Every incumbent is re-messaging. Our doc generator ships SR 26-2-shaped output today with the SR 11-7 lineage mapped for continuity.
- **Freddie Mac Seller/Servicer Guide, March 3, 2026** — every mortgage lender must document AI/ML governance. Forced buying event.
- **Wolters Kluwer June 2026 survey**: ~3-in-4 US banks lack documented rollback / routing / reporting capability. That is our TAM inside regulated banking.

---

## THE HARD OBJECTIONS — rehearsed responses

### "You're a solo non-engineering founder. Who builds this?"

> "I do today, with AI-assisted engineering — that's how 17 services and 100+ endpoints exist on a pre-seed timeline. That's not the long-term answer. The round is structured so 45% goes to engineering. I have two technical candidates in late conversation — [name them] — both with [domain] backgrounds. My commitment is a CTO close within 90 days of the round. If that misses, the board gets a vote on the next step. I'd rather be honest about that than pretend the bus factor doesn't exist."

### "What's the moat? Hash-chaining is a weekend's engineering. Drift detection is what Arize and Fiddler already sell."

> "You're right that the primitives aren't proprietary. The moat isn't the tech — it's becoming the system of record a regulator has already seen. Vanta's moat isn't SOC 2 monitoring; it's that auditors trust their evidence package. We're building the same thing for AI: depth in one regime, audited references, framework mappings that survive procurement review. The tech gets us to parity; the references compound. That's why I'm leading with depth in NYC LL144 instead of breadth across 29."

### "F5 paid $180M for CalypsoAI and called it immaterial to revenue. That sounds like 'feature, not platform.' Why isn't this an acqui-hire?"

> "At a $5M cap, that *is* the question that matters — and the comp math works either way. $150M+ acqui-hire floor on a $5M entry is real option value before we even talk standalone outcomes. I'm not going to oversell you a category-defining platform thesis the data doesn't support yet. What I will tell you is that the path to standalone goes through being the de facto evidence vendor in one regulated vertical — most likely US mid-tier banks under OCC AI guidance. If we land that, the conversation changes. If we don't, the comp set says the floor is still well above your entry."

### "You're at Google. Has GovernLayer been disclosed? Do you have written conflict-of-interest clearance?"

> "Yes, GovernLayer has been formally disclosed to Google. Built on personal time and equipment, no Google confidential information or code. I have written language on this I'm happy to share with your counsel under NDA. My invention-assignment, moonlighting, and non-compete clauses are reviewed — I'll quote them verbatim in your data room. Timeline to full-time on GovernLayer is [your honest answer: e.g., 'within 30 days of closing'] / [or: 'I'm running parallel for the next two quarters, here's why that's a feature not a bug']."

*(If you have not actually done this disclosure or had your clauses reviewed by an employment attorney — say "I'm completing the formal disclosure process now, with counsel" and book the attorney before the meeting.)*

### "Show me one signed paying regulated customer."

> "I cannot today. Pilot conversations are real but unsigned. I'm not going to embellish — the honest answer is zero ARR. What I can tell you is the pipeline state and the specific blocker on each. The number I want to walk out of this round with is one named paying design partner inside the first 90 days. That's the milestone I'd hold myself accountable to in your investment update."

### "Banks won't let you sit in the credit-decision path. This is a fantasy."

> "We don't sit in the path — we sit *beside* it. The upstream credit-decisioning model produces its output, hands it to `/credit/oversight` with the feature attributions, and gets back a governance verdict plus an ECOA-compliant adverse-action statement in one call. If the model's fine, the bank ships the decision as-is with our ledger record attached. If it's borderline, we've already routed the review to a Compliance Officer with a 4-hour SLA. We're not asking the bank to route production traffic through a startup — we're asking them to log every AI credit decision with us and let us handle the Reg B and SR 26-2 paperwork they were going to have to build anyway. Same posture as Vanta with SOC 2 evidence."

### "Isn't this just Zest AI?"

> "No, and this is exactly the differentiation to lean into. Zest **replaces** the underwriting model — you buy Zest, you rip out FICO or your in-house scorecard and run Zest's model. That's a multi-quarter procurement and a competitive vendor decision. We do not replace anything. We're the oversight layer that sits between whatever model the bank already runs — Zest, FICO, in-house, three of them stacked — and the final decision. We generate the ECOA reason codes, hash-chain the audit, escalate borderline denials, and emit the SR 26-2 doc. That means Zest's customers are our *buyers*, not our targets. Same for FairPlay: their post-hoc fairness analysis feeds into our decision-loop enforcement. We're a different point in the pipeline."

### "Your SAM exceeded your TAM in the previous version of this deck. What else is sloppy?"

> "Fair. That was loose deck arithmetic and I've fixed it — TAM is now sourced from Gartner AI TRiSM plus adjacent GRC and model-risk budgets, SAM is a clean subset, and SOM is the 3-year reachable revenue at $25–75M ARR. The deeper version of your question is whether I'm rigorous in my own domain. The fact that I caught and shipped the Omnibus update before this call is the better answer. Where else would you like me to be sharper?"

### "Your unit economics are modeled, not real. Why should I believe any of them?"

> "You shouldn't yet — and the deck now says so. The LTV is a range, the retention assumption is benchmarked not historical, and I've sensitivity-tested at 2-year and 4-year retention. After the first 10 paying customers I replace the model with actuals. The pre-seed thesis isn't 'trust the LTV.' It's 'is the wedge real, is the buyer reachable, and can the founder execute.' I'll defend those three; I won't defend a 5-year retention assumption I can't prove."

### "What happens if Microsoft bundles this into Purview for free?"

> "It already exists in early form — that's exactly the OSS toolkit we listed as a competitor. Two things keep this defensible. First, regulated buyers don't want free generalist OSS for compliance evidence; they want a vendor whose name an auditor recognizes, with an SLA and an indemnity. Credo AI's existence is the proof — they're funded against the same incumbent backdrop. Second, our wedge is regulatory depth in vertical workflows. Microsoft will go general; we'll go deep on banking and federal. Same reason Vanta survived Microsoft Compliance Manager."

### "Walk me through every dollar of the $1.5M, milestone by milestone. What gets cut at $750K?"

> "Full $1M: 45% engineering — 2 senior backend hires, infrastructure hardening, SOC 2 Type II audit fees. 30% sales — first AE hire, 6-month outbound program, design-partner conversion. 15% ops — legal, finance, employment counsel. 10% infrastructure — cloud, LLM API spend, observability.
>
> At $500K I cut to one engineering hire, defer the AE, run founder-led sales for two more quarters, and push SOC 2 Type II from Q3 to Q1 2027. Round still hits Q4 GA and Q4 first paying enterprise customer. ARR target compresses from $500K to ~$250K."

---

## CLOSE (30 seconds)

> "What I'm asking for: $1M at $5M cap. What you get: a live product, a founder who tracks his own regulatory space in real time, a category with a confirmed M&A floor at the $150–300M level, and a 90-day commitment on the CTO close.
>
> I'm not selling you a category-defining platform thesis the data doesn't support yet. I'm selling you a priced option on becoming the evidence vendor in one regulated vertical, with a realistic floor and an asymmetric upside. The disciplined version of this bet is to fund the next 12 months and re-underwrite when SOC 2 closes and the first paying regulated reference signs.
>
> What would you need to see in diligence to write the check?"

---

## AFTER THE CALL — same day

1. Send a thank-you in under 4 hours. One sentence per topic where they pressed hardest. One commitment with a date attached.
2. Send the data room link. Pre-stocked with: updated deck, cap table, current code metrics, Form 1120 / state filings, employment-agreement summary, list of named pilots with stage, and the 10 VC diligence questions with your answers.
3. Calendar follow-up: 2 weeks out, with a concrete update (e.g., "the design partner I mentioned has signed an LOI").

---

## DO-NOT-SAY LIST (these end rounds)

- ❌ "We're going to be the Vanta of AI governance" *(every governance founder says this; it's noise)*
- ❌ "Our patent is a moat" *(provisional patents aren't moats and sophisticated investors know it)*
- ❌ "We have no competition" *(immediate red flag)*
- ❌ "I lead AI governance for Gemini, DeepMind, Waymo, and Vertex" *(overclaim — say "support" or name your actual scope)*
- ❌ "We can reconstruct any decision exactly as it happened" *(LLM non-determinism makes this false; say "tamper-evident provenance")*
- ❌ "Compliance budgets are reallocating in real time" *(unprovable; say "US enforcement is live and procurement cycles are 6–18 months")*
- ❌ Any specific revenue number you do not have written customer evidence for

---

*Last updated to match deck MD5. Print before the call. Run through the open out loud three times.*
