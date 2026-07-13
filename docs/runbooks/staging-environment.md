# Add a Staging Environment on Railway

**Problem it fixes:** Every push to `main` currently deploys straight to production. No pre-production validation, no way to test SR 26-2 migrations or new endpoints against realistic data before customers see them. A single bad migration takes the whole platform down.

**Solution:** a second Railway service running the same codebase off a `staging` branch, with its own Postgres and its own env vars. Merge to `staging` first, verify, then merge to `main`.

## Architecture

```
main branch  ──►  Railway service `web`         ──►  api.governlayer.ai (prod)
                     └─ Postgres (prod)
                     └─ Redis (prod)
                     └─ env: ENVIRONMENT=production

staging branch  ──►  Railway service `web-staging`  ──►  staging.governlayer.ai
                        └─ Postgres (staging)
                        └─ Redis (staging)
                        └─ env: ENVIRONMENT=staging
```

## One-time Railway setup

### 1. Create the git branch

```bash
git checkout -b staging
git push -u origin staging
```

Set branch protection so nothing pushes to `staging` without CI green.

### 2. Add the staging service in Railway

In the `perpetual-abundance` project:

1. **New → GitHub Repo** → same repo (`Governlayer-stack/Governlayer`)
2. Name it **`web-staging`**
3. Under **Settings → Deploy → Branch**, set to **`staging`**
4. Same Dockerfile, same start command as prod (default)
5. Add a Postgres add-on to the same project — Railway lets you have multiple. Name it **`postgres-staging`**
6. Add a Redis add-on. Name it **`redis-staging`**

### 3. Environment variables for `web-staging`

```
ENVIRONMENT=staging
DATABASE_URL=${{Postgres-staging.DATABASE_URL}}
REDIS_URL=${{Redis-staging.REDIS_URL}}
SECRET_KEY=<generate fresh — DIFFERENT from prod>
ADMIN_KEY=<generate fresh — DIFFERENT from prod>

# Reuse prod values that don't leak state
GROQ_API_KEY=...
OPENROUTER_API_KEY=...

# Point Stripe at TEST mode
STRIPE_API_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_test_...
STRIPE_PRICE_STARTER=price_test_...

# Alerting → separate Slack channel so staging noise doesn't drown prod
SLACK_ALERT_WEBHOOK=<staging channel webhook>

# CORS — staging URLs only
CORS_ORIGINS=https://staging.governlayer.ai,http://localhost:3000
```

### 4. Custom domain (optional but recommended)

Under **Settings → Networking**, add `staging.governlayer.ai`. Point the CNAME at the Railway-provided target.

### 5. Verify the split

```bash
# Prod
curl https://web-production-bdd26.up.railway.app/health | jq .environment
# → "production"

# Staging
curl https://web-staging-xxxxx.up.railway.app/health | jq .environment
# → "staging"
```

## Workflow

```
feature branch  ──(PR)──►  staging  ──(promotion PR)──►  main
                            │                              │
                            ▼                              ▼
                       web-staging                        web
                       (validate 24h)                     (prod)
```

**Merge policy:** No `main` merge without a corresponding staging soak of at least 24 hours (or one full daemon cycle).

## Continuous verification on staging

Add a smoke test that hits staging after every deploy:

```bash
# .github/workflows/staging-smoke.yml (example)
on:
  push:
    branches: [staging]
jobs:
  smoke:
    runs-on: ubuntu-latest
    steps:
      - run: |
          # wait for deploy
          sleep 90
          # basic health + demo scenarios
          curl -fsSL https://staging.governlayer.ai/health
          SID=$(curl -sS https://staging.governlayer.ai/demo/scenarios | jq -r .session_id)
          curl -fsS -X POST https://staging.governlayer.ai/demo/scenarios/banking/run \
            -H "X-Demo-Session: $SID"
          curl -fsS https://staging.governlayer.ai/demo/ledger/verify/$SID
```

## Cost

Adding a staging service, staging Postgres, and staging Redis on Railway's paid tier: ~$10-20/month. This is worth it before the first paying customer signs.

## Escalation

- Staging deploy fails → GitHub Actions email + Slack (staging channel).
- Prod deploy fails → PagerDuty + Slack (prod channel).
