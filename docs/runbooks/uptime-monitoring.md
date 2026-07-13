# External Uptime Monitoring + Alerting

**Problem it fixes:** Right now if Railway drops the API, or a bad deploy 500s every request, you find out from a customer or an investor. There is no external service polling the platform and no alert path.

**Solution:** wire the free tier of **healthchecks.io** (or BetterUptime) to hit `/health` every 60 seconds and page on failure, plus a Slack webhook the app uses for its own critical events.

## Signals we need

| Signal | Where it comes from | Where it goes |
|---|---|---|
| Prod `/health` returns non-200 | External pinger (healthchecks.io) | PagerDuty + Slack |
| Ledger chain verify fails | Internal check (`send_alert`) | Slack `#alerts` |
| Kill switch fired | Webhook `agent.killed` + `send_alert` | Slack `#agent-events` |
| DSAR/deletion submitted | Webhook `privacy.deletion_submitted` + `send_alert` | Slack `#privacy` |
| Rate-limit sustained > 5min | Metrics scrape (future) | PagerDuty |

## Set up healthchecks.io (free tier)

1. Sign up at [https://healthchecks.io](https://healthchecks.io).
2. Create a check named **`governlayer-prod-health`**.
3. Under **Type**, choose **"Fetch a URL"**.
4. URL: `https://web-production-bdd26.up.railway.app/health`
5. Match: HTTP status = `200` AND response body contains `"status": "healthy"`.
6. Period: 60 seconds. Grace: 60 seconds. (Fires within ~2 minutes of an outage.)
7. Under **Integrations**, wire:
   - **Slack** → your `#alerts` channel (or a dedicated `#uptime`)
   - **Email** → founders@governlayer.ai
   - **PagerDuty** (optional, on paid tier) → your on-call rotation

Repeat for `governlayer-staging-health` pointed at `staging.governlayer.ai/health`.

## Set up the Slack webhook the app uses

The app has a built-in helper (`src/alerting.py`, function `send_alert()`) that posts to a Slack incoming webhook when `SLACK_ALERT_WEBHOOK` is set.

1. In Slack, create an **Incoming Webhook** app targeting `#alerts`.
2. Copy the webhook URL.
3. In Railway env for both `web` and `web-staging` services:
   ```
   SLACK_ALERT_WEBHOOK=https://hooks.slack.com/services/T.../B.../...
   ```
4. Redeploy.

Test it:

```bash
railway run --service web python3 -c \
  "from src.alerting import send_alert; send_alert('smoke test', 'ok', 'info')"
```

You should see a `:information_source: [PRODUCTION] smoke test` message in `#alerts`.

## Wire critical app events to send_alert

The following events should call `send_alert()` — add or verify each in code:

| Event | File | Level |
|---|---|---|
| Agent killed | `src/api/agent_registry.py` (kill switch) | `critical` |
| Framework CRITICAL rule failure | `src/api/governance.py` (framework overrides) | `error` |
| Ledger `/ledger/verify` fails | Add a daily cron | `critical` |
| Budget exhaustion | `src/api/agent_registry.py` (consume) | `warn` |
| Deletion request fulfilled | `src/api/privacy.py` (fulfill) | `info` |

The app already fires webhooks for these — `send_alert` is complementary, for the operator, not the customer.

## Daily ledger integrity check

Add a Railway Cron service (same pattern as the daemon runbook) that runs:

```bash
python -c "
import urllib.request, json, os
r = json.load(urllib.request.urlopen('https://web-production-bdd26.up.railway.app/ledger/verify'))
if not r.get('chain_intact'):
    from src.alerting import send_alert
    send_alert('LEDGER CHAIN BROKEN', json.dumps(r, indent=2), 'critical')
    exit(1)
"
```

Schedule: `0 6 * * *` — every day at 6 AM UTC. First alert of the day if the chain has been tampered with.

## Escalation ladder

1. **First page** (any check fails once) → Slack `#alerts` + email.
2. **Second page within 5 min** (persistent failure) → PagerDuty + phone.
3. **10+ min unresolved** → text `founders@governlayer.ai` via Twilio (future) and post to `#status`.

## Public status page (later)

Once you have a paying customer, add a public status page at `status.governlayer.ai` (Statuspage.io free tier, or Instatus). Auto-update from healthchecks.io.

## Cost

- healthchecks.io free tier: 20 checks, unlimited notifications.
- Slack webhooks: free.
- PagerDuty starter: $19/user/month (add later).

Total to bootstrap: **$0/month**.
