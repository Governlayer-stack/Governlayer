# PR Preview Deploys (Railway)

**Problem it fixes:** every PR merges into `main` and only then does it get exercised against real infrastructure. Bad regressions ship silently. Reviewers can't click through the PR without checking it out locally.

**Solution:** for every PR opened against `main` or `staging`, Railway spins up an ephemeral preview environment on the PR branch. The bot posts the preview URL as a PR comment. Preview environments are torn down when the PR closes.

## What the reviewer gets

A comment on every PR like:

> **🚀 Railway Preview**
> Preview URL: `https://gl-pr-142.up.railway.app`
> Environment: `pr-142`
> Deploy log: [Railway dashboard link]

They click, exercise the changed endpoints, comment.

## Setup (one-time)

### 1. Enable PR environments in Railway

Railway dashboard → `perpetual-abundance` → **Settings** → **Environments** tab → toggle **`PR Environments`** ON.

Railway now watches the linked GitHub repo. Every open PR gets a matching environment named `pr-<number>`.

### 2. Configure resource inheritance

Under the same page, set what a PR environment inherits from `production`:
- ✅ Environment variables — inherit but **override** the sensitive ones (see below).
- ❌ Database — **do not share.** Each PR gets its own Postgres.
- ❌ Redis — **do not share.** Each PR gets its own Redis.
- ✅ Codebase — same branch/commit as the PR.

### 3. Override sensitive variables per PR environment

In the PR environment template (Railway Settings → PR Environments → Variables), set:

```
ENVIRONMENT=preview
SECRET_KEY=<stable per-preview secret, does not need rotation>
ADMIN_KEY=<different from prod>
STRIPE_API_KEY=<test mode key>
STRIPE_WEBHOOK_SECRET=<test mode secret>
SENTRY_DSN=<separate Sentry project for previews so noise doesn't hit prod>
CORS_ORIGINS=*
```

Note the `CORS_ORIGINS=*` — CORS is loosened on previews so a reviewer can point local frontends at them. Never carry that setting into production; the `web` service overrides it.

### 4. Migrations run per-preview

Because our `startCommand` already runs `alembic upgrade head` non-blocking, every PR environment applies migrations against its dedicated preview database on first boot. Fresh DB, no cross-contamination.

### 5. GitHub PR comment integration

Railway posts the URL automatically once the deploy is healthy. To also post it into an internal Slack channel, add a step to `.github/workflows/pr-preview-notify.yml`:

```yaml
name: Notify Slack of PR Preview URL
on:
  pull_request:
    types: [opened, synchronize]
jobs:
  notify:
    if: github.event.pull_request.head.ref != 'main'
    runs-on: ubuntu-latest
    steps:
      - name: Slack ping
        env:
          WEBHOOK: ${{ secrets.SLACK_ALERT_WEBHOOK }}
        run: |
          curl -X POST "$WEBHOOK" -H 'Content-Type: application/json' -d "{
            \"text\": \":rocket: PR #${{ github.event.number }} preview: https://gl-pr-${{ github.event.number }}.up.railway.app\"
          }"
```

## Reviewer checklist for a preview

Every reviewer, on the PR:

- [ ] Preview loads `/health` → status `healthy`, environment `preview`.
- [ ] Endpoint(s) touched by the PR work end-to-end.
- [ ] Any new env var required by the PR is documented in the PR description.
- [ ] Ledger `/ledger/verify` still returns `chain_intact: true`.
- [ ] If the PR touches migrations: Alembic run in preview should have succeeded (no errors in the Railway logs).

## Teardown

Preview environments auto-destroy when the PR:
- is merged
- is closed without merging
- has no activity for 14 days (Railway default)

Nothing manual to do.

## Cost

Railway bills per environment for compute + database. A typical preview costs cents-to-dollars per day depending on how much traffic the reviewer generates. Set a **project spending cap** in Railway Settings → Usage → Spend Limit to prevent surprises.

## What this closes from the audit

- **P2-17 (Preview deploys per PR)** — done.
