# Move the GovernLayer Daemon to Railway (off your laptop)

**Problem it fixes:** Right now `scripts/governlayer_daemon.py` runs as a launchd agent on Ekene's MacBook. If the laptop sleeps, the network drops, or the OS updates, autonomous governance stops silently — with no alert.

**Solution:** run the daemon on Railway as a Cron service that hits the public API on a schedule. Zero dependency on local machines.

## What you're going to build

A second Railway service (`governlayer-daemon`) in the same project, that:
- Runs `python scripts/governlayer_daemon.py` on a schedule (default: every hour).
- Uses the same Docker image as the main API — no separate build.
- Talks to the API through the public Railway URL, so no in-cluster networking assumptions.
- Uses a bot service account (`daemon-agent`) whose password lives in Railway env.

## One-time setup

### 1. Register the bot account against the live API

The daemon authenticates as `daemon-agent`. Register it once via the public API using an existing admin user's token:

```bash
API="https://web-production-bdd26.up.railway.app"

# Get a fresh JWT for your admin account
TOKEN=$(curl -s -X POST "$API/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"founders@governlayer.ai","password":"YOUR_ADMIN_PASSWORD"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

# Register the bot (uses the automation router's dedicated endpoint)
curl -s -X POST "$API/automate/register-bot" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"bot_name":"daemon-agent","password":"REPLACE_WITH_STRONG_PASSWORD"}'
```

Note the `password` — you will paste it into the Railway env var below.

### 2. Add a new Railway service for the daemon

In the Railway dashboard for the `perpetual-abundance` project:

1. Click **New → GitHub Repo** and select `Governlayer-stack/Governlayer` (same repo).
2. Name the service **`governlayer-daemon`**.
3. Under **Settings → Build**, use the same Dockerfile (already default).
4. Under **Settings → Deploy**, replace the start command with:
   ```
   python scripts/governlayer_daemon.py
   ```
   (No `--loop` flag — Railway Cron invokes this once per fire.)
5. Under **Settings → Cron**, set:
   ```
   0 * * * *
   ```
   (every hour on the hour — bump to `*/15 * * * *` for every 15 minutes if you want tighter coverage).
6. Under **Variables**, set:
   ```
   GOVERNLAYER_API=https://web-production-bdd26.up.railway.app
   GOVERNLAYER_BOT=daemon-agent
   GOVERNLAYER_BOT_PASSWORD=<the password from step 1>
   ```
7. Deploy.

### 3. Confirm the daemon is firing

After the first hour hits, in the Railway service logs you should see:

```
[daemon] cycle started at 2026-07-13T18:00:00Z
[daemon] monitoring 4 systems
[daemon] system=GovernLayer API action=APPROVE
...
[daemon] cycle complete: 4 systems, 0 escalations, 0 blocks
```

If not:
- **401 on login** → the bot password in Railway does not match the one you set on the API. Reset and redeploy.
- **Connection refused / timeout** → `GOVERNLAYER_API` typo or the main service is down.
- **No log output at all** → Railway Cron not attached to the service. Confirm the schedule is set in the service settings.

### 4. Turn off the local launchd version

Once the Railway daemon is firing every hour successfully for 24 hours:

```bash
launchctl unload ~/Library/LaunchAgents/com.governlayer.daemon.plist
mv ~/Library/LaunchAgents/com.governlayer.daemon.plist \
   ~/Library/LaunchAgents/com.governlayer.daemon.plist.retired
```

Confirm no active daemon on the laptop:

```bash
launchctl list | grep governlayer   # should return nothing
```

## Health-check the Railway daemon from anywhere

```bash
# Manually trigger a run against the public API (useful for verifying config):
railway run --service governlayer-daemon \
  python scripts/governlayer_daemon.py --health-only
```

## Cost note

Railway Cron services bill for compute during execution only. A daemon that
runs for ~5 seconds every hour is effectively free on the free tier and
under $2/month on the paid tier.

## Escalation on daemon failure

The daemon does not currently self-page. Wire it up:

1. Add `RESEND_API_KEY` to the `governlayer-daemon` service Variables.
2. In `scripts/governlayer_daemon.py`, on any BLOCK/ESCALATE result, send a
   Resend email to `founders@governlayer.ai` with the incident summary.
3. Alternatively, POST to a Slack webhook stored in `SLACK_ALERT_WEBHOOK`.

Once implemented, add this to the setup steps above.
