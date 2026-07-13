# GovernLayer Infrastructure Audit — 2026-07-13

Mapped against the 8-layer / 40-control AI governance reference architecture.

**Verdict up front:**
- **Strong:** Layers 07 (Human Oversight) and 08 (Compliance & Audit) are close to reference — this is your moat.
- **Solid:** Layers 03 (Model Lifecycle), 04 (Data Security), 05 (Access Control), 06 (Agent Governance) — well-scaffolded, some enforcement gaps.
- **Partial:** Layers 01 (AI Inventory) and 02 (Data Foundation) — the primitives exist but the *shadow-AI discovery* and *data-catalog lineage* controls are underbuilt.
- **Cross-cutting infra gaps:** monitoring/alerting is thin, Redis dependency on Railway not verified, background daemon is running on your laptop not the cloud, no staging env, no tested restore-from-backup.

Legend: ✅ Solid  · ⚠️ Partial  · ❌ Missing

---

## Layer 01 — AI Inventory & Ownership

| Control | Status | Where it lives | Gap / next step |
|---|---|---|---|
| Shadow AI Detection | ❌ | — | **Missing.** No egress monitoring for LLM API domains, no CASB integration, no expense-report scraper. First thing to build if you sell to enterprises past pilot. |
| System Classification | ✅ | `/registry` (Model Registry) + `/agent-registry` — Tier, agent type, discovery source fields | — |
| Risk Tiering | ⚠️ | `src/api/risk.py` computes runtime tier per-decision; **there is no persistent system-level tier** driving control intensity | Add `risk_tier` field on RegisteredModel; make Tier 1 require MFA + full HITL + eval-gate on deploy |
| Ownership Assignment | ✅ | RegisteredModel has `owner` field | Enforce non-empty; add quarterly review reminder via `/compliance-calendar` |
| Vendor & Model Mapping | ✅ | `/vendor-risk` (9 routes) + `/lineage/models/*/datasets` | Missing: sub-processor tracking, provider-ToS diff-watching |

**Layer verdict:** Foundation is there but shadow-AI discovery is a real gap. For any enterprise pilot, this becomes an RFP question.

---

## Layer 02 — Data Foundation

| Control | Status | Where it lives | Gap / next step |
|---|---|---|---|
| Source Lineage | ⚠️ | `/lineage/models/*/datasets` links datasets to models | Column-level lineage not present; graph model exists but not populated by an ingest pipeline |
| Data Provenance | ⚠️ | Hash-chained ledger proves *decision* provenance; **not data-collection provenance** | Add ingest-time provenance metadata; make it immutable via the same ledger pattern |
| Quality Validation | ❌ | — | Missing. No pipeline-level completeness/schema checks. |
| Freshness Monitoring | ❌ | — | Missing. No per-dataset SLA + staleness alert. |
| Licensing & Consent | ⚠️ | Vendor-risk tracks provider ToS; **no per-dataset license flag** | Add `license` + `permitted_uses` fields on dataset records; propagate to RAG/training pipelines |

**Layer verdict:** Weakest area. Your data-catalog story is 60% built — you have the *destination* (lineage graph) but no *ingest pipeline* populating it. This is the area to invest in if a bank auditor asks "prove the model wasn't trained on data you didn't have rights to."

---

## Layer 03 — Model Lifecycle

| Control | Status | Where it lives | Gap / next step |
|---|---|---|---|
| Model Registry | ✅ | `/registry` (6 routes) + `/lineage/models` (versioned model cards) | — |
| Pre-Deploy Evaluation | ⚠️ | `/redteam` (7 routes) — adversarial harness exists | Not gated in CI/CD. Add a promotion-gate hook: no eval pass = no `is_production` flag. |
| Bias & Fairness Testing | ✅ | `/safety` (4 routes) + `/credit/oversight` protected-class proxy scanner | Extend disparate-impact 4/5ths testing beyond credit (currently only fair-lending) |
| Drift Monitoring | ✅ | `src/drift/detection.py` + `/govern` runs it on every decision | — |
| Retrain & Rollback | ⚠️ | Registry supports versions; **no automated rollback runbook** | Ship `POST /registry/models/{id}/rollback/{version}` + rehearsed test |

**Layer verdict:** Strong bones, needs the *promotion gate* and *rollback runbook* to be operational rather than theoretical.

---

## Layer 04 — Data Security & Privacy

| Control | Status | Where it lives | Gap / next step |
|---|---|---|---|
| Encryption at rest / in transit | ✅ | Postgres/Railway managed; TLS via Railway edge; HSTS enforced | Vector-store encryption: not yet in scope because you don't run a vector DB in prod today |
| PII Anonymization | ✅ | `/pii` (7 routes) — regex-first, Presidio-optional; PHI/PCI/SSN patterns | Add pre-flight redaction *middleware* option so upstream calls to Groq/OpenRouter get scrubbed automatically |
| Threat Detection | ⚠️ | `/threats` (4 routes) + `/ipi` scanner (3 routes) | Not tied to runtime; runs on-demand rather than continuously against prompt logs |
| Secure Storage | ⚠️ | Postgres for ledger + models; **no explicit vector-store, prompt-log, or checkpoint scoping** | If you add embeddings later, treat them as sensitive by default. Prompt logging in `/govern` is not currently retained. |
| Injection Defense | ✅ | `/ipi` (Indirect Prompt Injection scanner) with MITRE ATLAS mapping | Extend to indirect injection via retrieved content (RAG). Add output-filter middleware option. |

**Layer verdict:** Good defensive posture. Missing piece: **an LLM gateway pattern**. Right now each Achonye caller talks direct-to-provider; a gateway (proxy) would centralize redaction + logging + injection filtering.

---

## Layer 05 — Access Control

| Control | Status | Where it lives | Gap / next step |
|---|---|---|---|
| Role-Based Access | ✅ | `/rbac-views` (5 routes) + API key scopes (govern/audit/risk/scan) | — |
| Identity Management | ⚠️ | Human identities via `/auth` + `/oauth` + `/sso`; **agent identities not modeled as first-class principals** | Add `AgentPrincipal` model; every agent gets its own API key; no shared service accounts |
| Authentication | ✅ | JWT + API keys, MFA (`/mfa` 4 routes), OAuth (Google/GitHub/Microsoft), SSO (12 routes) | Enforce MFA on high-scope keys (audit + govern) — currently optional |
| Authorization Policies | ⚠️ | Scope-based checks on API keys | No policy-as-code (OPA/Cedar) — policies are hardcoded per-endpoint |
| Least Privilege | ⚠️ | API keys are long-lived by default | Add short-lived agent tokens (JWT with 5-min exp) + just-in-time elevation flow |

**Layer verdict:** Human identity story is complete. **Agent identity** is the gap — critical because you sell "agent governance."

---

## Layer 06 — Agent Governance

| Control | Status | Where it lives | Gap / next step |
|---|---|---|---|
| Tool Permissions | ⚠️ | `/agent-registry` records agent tools; `/agent-governance` policies exist | Deny-by-default not enforced at runtime; the registry stores tool lists but no gateway blocks unauthorized tool calls |
| Action Boundaries | ⚠️ | `/agi/dad.py` (Dual Advocate Debate) + `/agi/ccv.py` (Causal Chain Validation) score harmful paths | These are advisory scores — not hard blockers. Add hard-fail on `harm_score > 0.6`. |
| Autonomy Limits | ⚠️ | Rate limiting exists per-org; **no per-agent step/spend/recursion budget** | Ship a `Budget` model + middleware that decrements on each agent call; kill agent when budget hits 0 |
| Human-in-the-Loop | ✅ | `/hitl` (4 routes) with named regulatory routing (ECOA 4h, HIPAA 2h, BSA_AML 24h, UDAAP 8h) | This is your best-in-class layer. |
| Kill Switch | ❌ | — | **Missing.** No `POST /agents/{id}/kill` that terminates a running agent regardless of state. SR 26-2 explicitly requires this. |

**Layer verdict:** The HITL story is genuinely strong, but the **kill switch** and **enforced autonomy budgets** are must-haves before an OCC or Fed examiner will sign off. SR 26-2 §V.3 explicitly names kill-switch capability.

---

## Layer 07 — Human Oversight

| Control | Status | Where it lives | Gap / next step |
|---|---|---|---|
| Decision Review | ✅ | `/hitl/queue` + `/audit/history` — sampled review paths | Add tier-based sampling rate (Tier 1 = 100%, Tier 3 = 5%) |
| Escalation Paths | ✅ | HITL routing table with SLA per violation type | — |
| Output Validation | ✅ | `/govern` runs framework rule engine + drift + risk before allowing action; `/credit/oversight` gates on reason-code completeness | — |
| Explainability | ✅ | `/govern` returns framework findings + `factors[]`; `/credit/oversight` returns reason_codes + confidence gap; reasoning traces stored | Add SHAP-style feature attribution surface for non-credit models |
| Accountability Mapping | ✅ | Ledger records `audited_by` (email) + org_id per decision; ties to owner in registry | — |

**Layer verdict:** Reference-quality. This is your strongest layer.

---

## Layer 08 — Compliance & Audit

| Control | Status | Where it lives | Gap / next step |
|---|---|---|---|
| Regulatory Mapping | ✅ | `/frameworks` (3 routes) + `src/frameworks/` — 29 frameworks incl. NIST AI RMF, EU AI Act, ISO 42001, NYC LL144, Colorado SB 205, ECOA/Reg B, SR 26-2, OCC 2026-13, HIPAA, GDPR | — |
| Privacy Alignment | ⚠️ | `/residency` (6 routes) for region policies; **no DSAR workflow, no deletion cascade to embeddings/fine-tunes** | Add `POST /privacy/dsar` (data subject access request) + deletion pipeline that reaches all downstream stores |
| Model Documentation | ✅ | `/lineage/models/{id}/annex-iv` — EU AI Act Annex IV export; `/credit/sr26-2/{system}` — SR 26-2 MRM doc | Add: model cards for non-credit; DPIA templates |
| Incident Reporting | ✅ | `/incidents` (4 routes) — full lifecycle; taxonomy defined | Add: mandatory-reporting clock per regime (some regulators require notice in 24h) |
| Audit Trails | ✅ | Hash-chained ledger, SHA-256, `GET /ledger/verify` in 12ms; per-decision `previous_hash + current_hash` | This is the crown jewel. |

**Layer verdict:** This is the layer investors are paying for. Only real gap is DSAR/deletion (GDPR Article 17) — that's a certain FAQ once you sell into an EU customer.

---

## Cross-cutting infrastructure hygiene (outside the 40-control model)

### Deployment (Railway)

| Item | Status | Notes |
|---|---|---|
| Multi-stage Docker build | ✅ | Non-root user, layered install |
| Health check wired | ✅ | `/health` returns 200; used by Railway healthcheck + Docker HEALTHCHECK |
| Restart policy | ✅ | ON_FAILURE, 5 retries |
| Uvicorn workers | ⚠️ | 2 workers only. Bump to `(2 * CPU) + 1` when you upgrade Railway plan. |
| Readiness probe | ❌ | No `/ready` or `/readyz` distinct from liveness. Add one so Railway doesn't route traffic before DB is warm. |
| `/metrics` endpoint | ⚠️ | Returns 403. Either open it to Prometheus scraper (with auth) or document how to consume it. |
| Custom domain (`www.governlayer.ai`) | ✅ | Live, returning same content as Railway URL |
| TLS | ✅ | Railway-managed |
| Staging environment | ❌ | **Missing.** You deploy from `main` straight to production. High risk. Add a `staging` Railway service off a `staging` branch. |

### Database (Postgres)

| Item | Status | Notes |
|---|---|---|
| Managed Postgres | ✅ | Railway |
| Alembic migrations | ✅ | Configured |
| Connection pooling | ⚠️ | SQLAlchemy default; verify pool_size for 2-worker deployment |
| Backups | ⚠️ | Railway does automatic backups — **you have not tested restore**. Do that this month. |
| PITR (point-in-time recovery) | ❓ | Depends on Railway plan — check |

### Cache / broker (Redis)

| Item | Status | Notes |
|---|---|---|
| Redis configured | ✅ | `redis_url` in config |
| Rate limiting backed by Redis | ✅ | `src/middleware/rate_limit.py` |
| **Is Redis actually running in Railway?** | ❓ | You need to verify. If `REDIS_URL` points at `redis://localhost:6379/0` in Railway, rate limiting silently no-ops. |

### Background jobs

| Item | Status | Notes |
|---|---|---|
| GovernLayer daemon (`scripts/governlayer_daemon.py`) | ⚠️ | Runs on your **laptop** via launchd, not on Railway. Kill your laptop, kill the daemon. Move it to a Railway cron service or Railway Cron Jobs. |
| Webhook dispatcher (`src/api/webhooks.py:dispatch_event`) | ⚠️ | Synchronous inline — blocks the request thread. Move to a background task queue (Celery/RQ/Dramatiq). |
| n8n workflow automation | ⚠️ | Also local-only. Not production. |

### Monitoring & observability

| Item | Status | Notes |
|---|---|---|
| Structured JSON logging | ✅ | `src/middleware/logging.py` |
| Request correlation IDs | ✅ | `RequestCorrelationMiddleware` |
| Metrics middleware | ✅ | Present; `/metrics` gated |
| Sentry error tracking | ⚠️ | Code path exists (`init_sentry`) — **verify SENTRY_DSN is set in Railway env**. If not, you have no error notifications. |
| Alerting / paging | ❌ | No PagerDuty / Opsgenie / Slack alert integration. |
| Uptime monitoring | ❌ | No external monitor (BetterUptime, Pingdom, healthchecks.io) hitting `/health`. |
| Log retention | ❓ | Railway keeps logs for N days depending on plan — confirm |

### Security

| Item | Status | Notes |
|---|---|---|
| CORS locked to `governlayer.ai` in prod | ✅ | Verified |
| Per-path CORS overlay on `/demo/*` | ✅ | Shipped 2026-07-08 |
| HSTS + Permissions-Policy + CSP | ✅ | Middleware present |
| Non-root Docker user | ✅ | |
| Rate limiting | ✅ | Redis-backed |
| MFA available | ✅ | `/mfa` routes |
| SECRET_KEY guard | ✅ | Refuses to start with default value |
| Secrets rotation cadence | ❌ | No documented rotation schedule for SECRET_KEY, GROQ_API_KEY, STRIPE_*, OAUTH_* |
| WAF / DDoS | ⚠️ | Rely on Railway edge. No Cloudflare / Fastly in front. For enterprise banking pilots, add Cloudflare. |
| Dependency scanning | ❓ | GitHub Actions does lint + test — verify Dependabot or `pip-audit` in CI |

### CI/CD

| Item | Status | Notes |
|---|---|---|
| GitHub Actions on push/PR | ✅ | Lint + test |
| Auto-deploy on push to `main` | ✅ | Railway does this |
| Preview deploys per PR | ❌ | Nice-to-have; Railway supports it |
| Rollback path | ⚠️ | Railway console has rollback; not scripted / rehearsed |

### Third-party integrations

| Integration | Status | Notes |
|---|---|---|
| Stripe (billing) | ✅ | 4 endpoints; webhook signed |
| Groq (fast LLM) | ✅ | `GROQ_API_KEY` in Railway |
| OpenRouter (universal LLM) | ✅ | Set |
| Ollama (local LLM) | ⚠️ | Only running on your laptop — Railway can't call it. Achonye should route around Ollama for cloud requests. |
| Resend (email) | ⚠️ | Optional; falls back to SMTP or dev-mode logging |
| OAuth (Google/MS/GitHub) | ⚠️ | Client IDs set — **verify redirect URLs point to `www.governlayer.ai` not Railway URL** |
| Sentry | ❓ | Verify DSN set |
| **Ollama in Railway** | ❌ | Not deployed. If a cloud caller triggers `use_local_llm=True`, request will hang. Guard against this. |

---

## Prioritized fix list (do these in order)

### 🔴 P0 — this month, no exceptions

1. **Verify Railway `REDIS_URL` points at a real Railway Redis add-on**, not `localhost`. If it's localhost, rate limiting is silently broken across everything.
2. **Verify `SENTRY_DSN` set in Railway.** If not, you have no error alerts on prod.
3. **Move the daemon off your laptop.** Railway Cron Jobs or a scheduled Railway service. Right now if your MacBook sleeps, autonomous governance sleeps with it.
4. **Test a database restore.** Take a Railway backup, spin up a scratch Postgres, restore into it. Do this before you need it.
5. **Kill switch.** `POST /agents/{id}/kill` that terminates an in-flight agent regardless of its cooperation. SR 26-2 §V.3 requires this and you're claiming SR 26-2 coverage on the pitch.

### 🟡 P1 — next 30 days

6. **Staging environment.** A `staging` Railway service off a `staging` git branch. Never deploy straight to prod again.
7. **Uptime monitoring.** External pinger (healthchecks.io free tier or BetterUptime) hitting `/health` every minute → PagerDuty / Slack alert.
8. **Agent identities as first-class principals.** No shared service accounts. Every agent gets its own scoped API key.
9. **Enforced autonomy budgets.** `Budget` model with step/spend caps decremented per agent call.
10. **DSAR + deletion cascade** for GDPR readiness.

### 🟢 P2 — next quarter

11. Shadow-AI discovery (egress-monitoring integration).
12. Data-catalog ingest pipeline populating the lineage graph.
13. Promotion gate in CI/CD tied to `/redteam` eval pass.
14. Async webhook queue (Celery/RQ).
15. Cloudflare in front of Railway for banking enterprise pilots.
16. Secrets-rotation runbook + documented cadence.
17. Preview deploys per PR.

---

## The one-sentence summary

You have an unusually strong Layers 07 + 08 story (HITL SLA routing + hash-chained ledger + framework crosswalk are best-in-class), a solid Layers 03–06 stack with predictable gaps (agent identity, kill switch, enforced budgets), and a weaker Layers 01–02 story (shadow-AI + data provenance) that will become an RFP issue when you move past pilots. **The single most urgent fix is not any of that — it's confirming your Redis and Sentry env vars are wired in Railway and moving the daemon off your laptop.**
