# Put Cloudflare in Front of Railway

**Problem it fixes:** Railway's edge is fine for a pre-seed startup, but the moment you take a mid-tier US bank into procurement they will ask about **WAF, DDoS protection, geo-blocking, TLS 1.3 enforcement, IP allow-lists,** and a **status page**. Railway alone answers "kind of" to most of these. Cloudflare in front answers "yes, here's the config" to all of them.

**Solution:** put Cloudflare between the internet and Railway. Railway keeps serving the app; Cloudflare terminates TLS at the edge, applies rules, and proxies to Railway.

## Architecture

```
Internet
   │
   ▼
Cloudflare (proxied, orange cloud)
   ├─ WAF (OWASP + custom rules)
   ├─ Rate limiting (per-IP + per-path)
   ├─ Bot management (challenge suspected bots)
   ├─ Geo-blocking (opt-in per path)
   └─ Cache (static assets only — never API responses)
   │
   ▼ (origin request, TLS 1.3, mTLS optional)
   │
Railway edge → web service (uvicorn) → Postgres / Redis
```

## Prerequisites

- Own `governlayer.ai` DNS at a registrar (you already do).
- A Cloudflare account (free tier is enough to start; upgrade to Pro at ~$25/mo when you land the first regulated customer).

## Step 1 — Add the domain to Cloudflare

1. Cloudflare dashboard → **`Add site`** → enter `governlayer.ai` → **Free** plan.
2. Cloudflare scans your existing DNS and shows you the records. Verify they match your registrar.
3. Cloudflare gives you two nameservers (something like `alan.ns.cloudflare.com` + `carol.ns.cloudflare.com`).
4. At your registrar, replace the current nameservers with those two.
5. Wait for propagation (up to 24h; usually 1-2 hours).

## Step 2 — Point DNS at Railway with proxying enabled

In Cloudflare DNS:

| Type | Name | Content | Proxy status |
|---|---|---|---|
| CNAME | `@` | `web-production-bdd26.up.railway.app` | 🟠 **Proxied** |
| CNAME | `www` | `web-production-bdd26.up.railway.app` | 🟠 **Proxied** |
| CNAME | `staging` | `web-staging-xxxxx.up.railway.app` | 🟠 **Proxied** |
| CNAME | `status` | `governlayer.statuspage.io` (once you add it) | ⚪ **DNS only** |

The orange cloud (proxied) is what puts Cloudflare in the request path.

In Railway settings for the `web` service, under **Networking**, add both `governlayer.ai` and `www.governlayer.ai` as custom domains. Railway will issue Let's Encrypt certs — leave that on.

## Step 3 — SSL/TLS

Cloudflare SSL/TLS settings:
- **Encryption mode:** **`Full (strict)`** — encrypts both edge and origin, validates Railway's cert.
- **Minimum TLS version:** **`TLS 1.3`**.
- **Automatic HTTPS Rewrites:** ON.
- **Always Use HTTPS:** ON.
- **HTTP/3 (QUIC):** ON.
- **TLS 1.3 Zero-RTT:** OFF (mutations replayed on 0-RTT are a real problem for anything with side effects).

## Step 4 — WAF rules

Cloudflare **Security → WAF → Managed rules**:
- **Cloudflare Managed Ruleset:** ON, "High" sensitivity.
- **OWASP Core Ruleset:** ON, paranoia level 2.

Add **custom rules** under WAF → Custom rules:

1. **Block admin endpoints from anywhere except your allow-list:**
   ```
   (http.request.uri.path contains "/admin/" and not ip.src in {A.B.C.D E.F.G.H})
   ```
   Action: **Block**.

2. **Rate-limit unauth demo endpoints:**
   Under **Security → Rate limiting rules**:
   ```
   Path: /demo/*
   Rate: 60 requests / 60 seconds per IP
   Action: Managed challenge
   ```
   The app already rate-limits, but doing it at the edge saves origin cycles.

3. **Rate-limit auth endpoints (defends registration spam):**
   ```
   Path: /auth/register OR /auth/login
   Rate: 5 requests / 60 seconds per IP
   Action: Block for 10 minutes
   ```

4. **Challenge suspicious countries (later; requires paid plan):**
   ```
   ip.geoip.country in {"RU" "KP" "IR"} and http.request.uri.path contains "/v1/"
   Action: Managed challenge
   ```

## Step 5 — Cache rules

Cloudflare **Rules → Cache rules**:

- **Cache the demo walkthrough HTML** (rarely changes):
  ```
  URI path equals /pitch/demo
  Cache eligibility: Eligible for cache
  Edge TTL: 5 minutes
  ```

- **Never cache the API surface**:
  ```
  URI path starts with any of /v1/ /demo/ /admin/ /health /openapi.json
  Cache eligibility: Bypass cache
  ```

Skipping the cache for API paths is critical — you never want a stale governance decision returned from cache.

## Step 6 — Turnstile on demo

Add Cloudflare Turnstile (their captcha alternative) to the `/pitch/demo` page. The demo endpoints are already rate-limited server-side, but Turnstile filters bots before they hit your rate limits.

This is a code change: add a Turnstile widget to `docs/pitch/demo-walkthrough.html`, verify the token server-side before hitting the API. Do this when you take the first paying customer, not before.

## Step 7 — Observability

Cloudflare → **Analytics & Logs**:
- Enable **Analytics** (free).
- Add **Logpush** to send request logs to S3 / GCS (Pro plan).

Set up a Cloudflare-side alert: **Notifications → Add** → "HTTP 5xx errors > 5% for 5 min". Notification target: your Slack `#alerts` channel.

## Step 8 — Confirm end-to-end

```bash
# From your machine — should return healthy JSON, served through Cloudflare
curl -sI https://www.governlayer.ai/health | grep -E "^(HTTP|server|cf-)"

# Look for these headers:
#   HTTP/2 200
#   server: cloudflare
#   cf-ray: <some-id>
```

If you see `server: cloudflare`, you're proxying correctly.

## Cost

- Cloudflare Free: sufficient for the first 6 months.
- Cloudflare Pro ($25/mo): needed once you want geo-blocking + logpush + advanced WAF.
- Cloudflare Business ($200/mo): needed if the bank asks for a signed BAA / DPA. Get it right before your first regulated contract signs.

## What this closes from the audit

- P2-15 (Cloudflare in front) — **done** when the CNAMEs are proxied and WAF rules are on.
- Adjacent: adds DDoS protection, geo-blocking, TLS 1.3 enforcement — all things banks will ask about in procurement.

## Escalation on Cloudflare-side incident

- Cloudflare status page: https://www.cloudflarestatus.com
- If Cloudflare is down globally, temporarily turn off the orange cloud on the CNAMEs (DNS-only) to fall back to Railway direct. Traffic still works, minus WAF/rate-limit protection.
