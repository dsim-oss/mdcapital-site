# mdcapital.fund — Auth Setup

Server-side auth via Vercel Edge Middleware. The password no longer lives in the source. Replaces the old client-side SHA-256 "polite gate."

## What's deployed

- **`middleware.js`** (root) — Edge Middleware. Gates all `/MD_Capital_*.html` and `/demo/*` routes. Verifies an HMAC-signed cookie. Redirects to `/` if missing/invalid.
- **`api/login.js`** — Edge Function at `/api/login`. POST `{password}` → if correct, returns HttpOnly signed cookie (`mdc_auth`, 30-day expiry).
- **`index.html`** — login UI rewired to POST to `/api/login` instead of doing a client-side hash check. Password no longer in source.

## What stays public (no auth required)

- `/` (the login/portal page itself)
- `/weekly.html` (the current investor letter — meant to be shareable)
- `/letters/*` (the dated letter archive)
- `/api/*` (so the login endpoint is reachable)
- Static assets (`favicon.svg`, `robots.txt`, images, fonts)

## What's protected (requires valid cookie)

- `/MD_Capital_Dashboard.html`
- `/MD_Capital_Analytics.html`
- `/MD_Capital_Signal_System.html`
- `/MD_Capital_Sentiment.html`
- `/MD_Capital_Weekly.html`
- `/demo/*`

---

## One-time setup (your action — Vercel dashboard)

1. **Vercel dashboard → your `mdcapital-site` project → Settings → Environment Variables.**
2. Add **two** variables for **Production** (and Preview if you use it):

   | Name | Value | Notes |
   |---|---|---|
   | `SITE_PASSWORD` | *whatever password you want* | This is what you and Mike will type to log in. Pick something strong. Do NOT reuse `HardeyPrep`. |
   | `JWT_SECRET` | *32+ char random string* | Cookie signing secret. Generate one with: `openssl rand -hex 32` in Terminal, or any password generator. Keep it private — anyone who gets it can forge auth cookies. |

3. **Redeploy.** Vercel will auto-deploy when you push the new code, but if you set the env vars after the push, hit "Redeploy" on the latest deployment so the new vars take effect.

4. **Test:**
   - Visit `mdcapital.fund/MD_Capital_Dashboard.html` directly (incognito window) — should redirect to `/`
   - Enter your `SITE_PASSWORD` on the portal page → should land on portal selector
   - Click into any dashboard → should now succeed
   - Open `mdcapital.fund/weekly.html` directly — should load without auth (public letter)

## Rotating the password later

Just change the `SITE_PASSWORD` env var in Vercel and redeploy. No code changes. Existing cookies stay valid until they expire (30 days) — to invalidate everyone immediately, also rotate `JWT_SECRET`.

## What this fixes vs. the old setup

| | Old (client-side SHA-256) | New (server-side cookie) |
|---|---|---|
| Password in page source | YES (`HardeyPrep` in comments AND plaintext fallback) | NO |
| Hash visible to view-source | YES | N/A (cookie is server-issued) |
| Brute-force feasible | YES (no rate limit on the server) | RATE-LIMITED (5 client attempts → 15 min lockout, plus you can add Vercel rate-limiting on the function) |
| Anyone with hash → can log in | YES | NO (need real password to mint cookie) |
| Cookie tampering possible | N/A | NO (HMAC signature verified by middleware) |
| Cookie steal-able by JS | N/A | NO (HttpOnly) |

## Files to commit

When you push via GitHub Desktop, you'll see these new/changed files:

- `middleware.js` (new)
- `api/login.js` (new)
- `index.html` (modified — login form rewired)
- `AUTH_SETUP.md` (this file — feel free to keep or delete)
