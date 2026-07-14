# Secrets Rotation Runbook

**Purpose:** every secret has a defined lifetime and rotation procedure. This runbook says what, when, and how, and where the evidence lives.

**Frequency:** rotation cadence per secret is below. Every rotation is logged to the audit ledger via `/mutation_logs` so it's regulator-visible.

## Secrets inventory

| Secret | Where it lives | Rotation cadence | Rotation procedure |
|---|---|---|---|
| `SECRET_KEY` (JWT signing) | Railway env, `web` and `web-staging` | **Every 90 days**, or immediately after any suspected compromise | See §1 below — requires session invalidation |
| `ADMIN_KEY` | Railway env, `web` and `web-staging` | **Every 90 days** | See §2 — one-liner |
| `GROQ_API_KEY` | Railway env | **Every 180 days** or when Groq notifies of a breach | See §3 |
| `OPENROUTER_API_KEY` | Railway env | **Every 180 days** | See §3 |
| `STRIPE_API_KEY` | Railway env | **Every 12 months** | See §4 |
| `STRIPE_WEBHOOK_SECRET` | Railway env + Stripe dashboard | **Every 12 months** | See §4 |
| `RESEND_API_KEY` | Railway env | **Every 12 months** | See §3 |
| OAuth client secrets (Google, Microsoft, GitHub) | Railway env + provider console | **Every 12 months** or on provider notification | See §5 |
| `SENTRY_DSN` | Railway env | Rotate only if leaked publicly (it's semi-public by design) | See §6 |
| Database password | Railway managed | **Managed by Railway** — bump when they rotate | See §7 |
| Redis password | Railway managed | **Managed by Railway** | Same as §7 |
| Railway project tokens (like the one used for CI/scripts) | Individual tokens | **Rotate before every calendar quarter,** and revoke immediately after any one-off use | See §8 |
| `SLACK_ALERT_WEBHOOK` | Railway env + Slack app | **Every 12 months** or on Slack app suspicion | See §9 |
| `PRIVATE_PITCH_SLUG` | Railway env | Rotate whenever a deck is meant to be revoked for that specific investor | See §10 |

## §1 — `SECRET_KEY` (JWT signing)

⚠ **High blast radius:** rotating this invalidates every JWT — every logged-in user must re-login.

```bash
# 1. Generate the new key locally (do NOT commit anywhere)
NEW_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(64))')

# 2. In Railway dashboard, `web` service → Variables → edit SECRET_KEY → paste
#    (or via CLI:) railway variables --set "SECRET_KEY=$NEW_KEY"

# 3. Redeploy (Railway does automatically on env change)

# 4. Announce to your workspace users:
#      "You may be asked to log in again — brief scheduled maintenance."
```

**Rollback:** if something breaks and you can identify it within 15 minutes, paste the old key back. Cached JWTs stay valid.

## §2 — `ADMIN_KEY`

Low blast radius — only affects `/admin/*` endpoints.

```bash
NEW_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')
# Set in Railway → wait for redeploy → replace the value in your password manager.
```

Verify with:

```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "X-Admin-Key: $NEW_KEY" \
  https://web-production-bdd26.up.railway.app/admin/infra-check
```

Expect `200`.

## §3 — Cloud LLM API keys (Groq, OpenRouter, Resend)

1. In the provider dashboard, create a **new** API key (don't delete the old one yet).
2. Update the Railway env var with the new value.
3. Wait 5 minutes and confirm requests succeed (make a real call via `/govern` or `/health`).
4. **Then** revoke the old key in the provider dashboard.

The two-key overlap window means zero downtime.

## §4 — Stripe (`STRIPE_API_KEY` + `STRIPE_WEBHOOK_SECRET`)

Stripe supports rolling keys with an overlap window explicitly.

1. Stripe dashboard → Developers → API keys → **Roll key**. Stripe offers 12h, 24h, or 7d overlap.
2. Paste the new secret key into Railway.
3. Redeploy.
4. Watch `/billing/webhook` in Stripe's Webhook attempts log for successful deliveries with the new signing secret (if you rolled that too).
5. Stripe automatically retires the old key after the overlap window.

## §5 — OAuth client secrets

Google, Microsoft, GitHub each have their own dashboards:
- **Google:** [console.cloud.google.com](https://console.cloud.google.com) → APIs & Services → Credentials → your OAuth client → Add secret → Update Railway → Wait 48h → Delete old secret.
- **Microsoft:** Azure Portal → App registrations → your app → Certificates & secrets → New secret → Update Railway → Delete old.
- **GitHub:** github.com/settings/developers → your OAuth app → Generate new client secret → Update Railway → Delete old.

## §6 — Sentry DSN

Sentry DSNs are semi-public (they're embedded in frontend code). Rotate only if:
- The DSN was leaked in a way that lets someone push fake events (annoying but not critical).
- You want to reorg by environment/project.

Rotation: create a new project → point Railway env to its DSN → delete old project.

## §7 — Database and Redis passwords

Railway manages these. If Railway rotates internally, `${{Postgres.DATABASE_URL}}` and `${{Redis.REDIS_URL}}` reference variables update automatically.

Force a rotation:
1. Railway dashboard → Postgres service → **Regenerate credentials**.
2. Any service using the `${{Postgres.DATABASE_URL}}` reference variable picks up the change on next deploy — no manual copying.

## §8 — Railway project tokens

Ephemeral by design. Any token issued for a specific task (CI run, migration, this-Claude-session) is:
1. Created with a specific name and short lifetime intention.
2. Revoked at the Railway dashboard immediately after the task completes.
3. Logged in this runbook's ledger (§11) with created/revoked timestamps.

## §9 — Slack webhook

If leaked, someone can spam your `#alerts` channel. Rotate:
1. Slack app → Incoming Webhooks → **Deactivate** the old one.
2. Create a new one.
3. Update `SLACK_ALERT_WEBHOOK` in Railway.

## §10 — `PRIVATE_PITCH_SLUG`

Every private-pitch URL is `governlayer.ai/pitch/{slug}`. If an investor is now hostile or the deck is stale, rotate:
1. Regenerate the slug (`python3 -c 'import secrets; print(secrets.token_urlsafe(16))'`).
2. Update Railway env.
3. Old URL now 404s.
4. Send the new URL to the still-friendly investors.

## §11 — Evidence log

Every rotation is a mutation event. Record it via `POST /mutation_logs`-style — or simpler, keep a table here:

| Date | Secret | Rotated by | Reason | Old value hash (SHA256, first 8 chars) | Reference |
|---|---|---|---|---|---|
| 2026-07-14 | ADMIN_KEY | Ekene | Setup rotation cadence baseline | (initial) | this runbook |

Copy this table to a live Google Sheet or append to `mutation_logs` via a scheduled script.

## §12 — Rotation reminders

Set a calendar reminder chain:

- **Every 90 days** (Jan 15, Apr 15, Jul 15, Oct 15): SECRET_KEY + ADMIN_KEY rotation.
- **Every 180 days** (Feb 1, Aug 1): Groq + OpenRouter + Resend.
- **Annually** (Jan 1): OAuth + Stripe + Slack + Sentry review.

Also: **immediately** rotate `SECRET_KEY` if:
- You commit an env file to git by mistake.
- A laptop with an env file is lost / stolen.
- Any team member leaves.
- A Railway member is removed (in case they had console access to variables).

## What this closes from the audit

- **P2-16 (Secrets-rotation runbook + documented cadence)** — done.
