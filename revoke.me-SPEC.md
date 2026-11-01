# revoke.me — Project Spec

## What this is

A single-page, fully static website ("revoke.me") hosted on GitHub Pages. A user pastes a
leaked secret/token; the page identifies the provider, shows them *whose* credential it is
(identity info), and revokes the token directly from the browser against the provider's
self-revoke endpoint. There is no backend, no server, no database, no logging. Everything
runs client-side against the provider's public API.

Target audience: people doing incident response on leaked credentials (found in commits,
logs, config files) who need to kill a token *now* with only the token string in hand.

## Hard constraints

1. **Static site.** Plain HTML/CSS/JS. No build step required (a simple one is acceptable
   but not valuable). No framework. Zero external dependencies — no CDN, no web fonts, no
   analytics, no third-party scripts, no images from other origins.
2. **The pasted secret never leaves the browser except to the provider's own revoke/info
   endpoints.** Enforce this mechanically with the CSP below, and never persist it:
   no localStorage, no sessionStorage, no cookies. Hold it in a JS variable only, wipe on
   page unload, and provide a "wipe" button.
3. **Never log the token** to console, error messages, or the page URL.
4. **Do not change the request shapes below.** Every content-type, header, and parameter
   placement is dictated by CORS rules. Do NOT "clean up" requests into JSON bodies or
   add Authorization headers where the spec says not to — those changes will silently
   break revocation (see "Why the request shapes matter").

## Security headers (in the HTML)

```html
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none';
               script-src 'self';
               style-src 'self';
               connect-src https://api.github.com https://slack.com
                           https://oauth2.googleapis.com https://api.dropboxapi.com
                           https://gitlab.com;
               base-uri 'none';
               form-action 'none'">
<meta name="referrer" content="no-referrer">
```

The `connect-src` allowlist is the page's trust proof: it is technically incapable of
sending the secret anywhere except these five provider endpoints. Display this fact in the
page footer ("view source — nothing here phones home").

UI requirements: masked input with reveal toggle; provider auto-detection with a manual
provider dropdown as fallback (some token types aren't reliably pattern-matchable).

## Why the request shapes matter (context for the implementer)

Browser cross-origin requests come in two classes:

- **Simple requests** (POST with `Content-Type: application/x-www-form-urlencoded`, no
  custom headers) are *sent and executed by the server* even when the server sends no CORS
  headers. The response is unreadable unless the server includes
  `Access-Control-Allow-Origin`, but the revoke still happens. This is why Slack and Google
  calls below use form bodies and no Authorization header.
- **Preflighted requests** (JSON content-type, DELETE method, or custom headers like
  `Authorization` / `PRIVATE-TOKEN`) require the server to answer an OPTIONS preflight
  first. If it doesn't, the browser never sends the real request — the revoke silently
  never happens. This is why Twilio and npm are NOT in this spec (their APIs don't permit
  browser calls), and why GitHub/Dropbox's header usage is safe (their APIs explicitly
  allow these headers via CORS).

Sources for these claims: https://docs.github.com/en/rest/using-the-rest-api/using-cors-and-jsonp-to-make-cross-origin-requests ,
https://developers.google.com/identity/protocols/oauth2/javascript-implicit-flow ,
https://stackoverflow.com/questions/71293668/request-header-field-authorization-is-not-allowed-by-access-control-allow-headers

## The flow (state machine)

For every provider:

1. **Detect** provider from the token pattern; allow manual override via dropdown.
2. **Pre-check** (info/whoami call). Shows the user the compromised identity (login, team,
   account) and confirms the token is live. If the token is already dead, stop and say
   "already invalid — nothing to do."
3. **Confirm**: display identity info + a single "Revoke" button. No auto-revocation on
   paste.
4. **Revoke** via the provider's endpoint.
5. **Post-check**: re-run the info call. Live-before + dead-after = confirmed revoked.
   If the post-check returns 200 immediately after revoking, wait 1 second and retry once
   (propagation delay) before reporting failure.
6. **Report** one of: `CONFIRMED_REVOKED`, `ALREADY_DEAD`, `SENT_UNVERIFIED`,
   `FAILED` (with the HTTP status or opaque-response caveat).

All requests need a timeout (suggest 15s) and error classification: network error vs
HTTP 4xx/5xx vs opaque (`response.type === 'opaque'`) — an opaque response means the
request was sent but cannot be read; report as `SENT_UNVERIFIED`, not as an error.

## Provider implementations

### 1. GitHub

- **Detect:** token starts with `ghp_`, `gho_`, `ghu_`, `ghr_`, or `github_pat_`.
- **Pre-check:** `GET https://api.github.com/user`
  - Headers: `Authorization: Bearer <token>`, `Accept: application/vnd.github+json`
  - `200` → token live; show `login` and `name` from the JSON body. The response header
    `X-OAuth-Scopes` lists the token's scopes — display it (GitHub's CORS config exposes
    this header to browsers). `401` → dead. `403` → likely the token is fine but the
    request was blocked (or rate-limited); surface the message.
- **Revoke:** `POST https://api.github.com/credentials/revoke`
  - Headers: `Accept: application/vnd.github+json`,
    `Content-Type: application/json`
  - Body: `{"credentials":["<the token>"]}`
  - **Do NOT send any Authorization header** — this endpoint is unauthenticated only;
    authenticated calls return 403.
  - `202` = accepted. Rate limit: 60 unauthenticated requests/hour per IP; handle
    `422`/`429` with a clear message.
  - Reference: https://docs.github.com/en/rest/credentials/revoke
- **Post-check:** repeat the pre-check `GET /user`; `401` confirms revoked.

### 2. Slack

- **Detect:** token starts with `xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-`, or `xapps-`.
- **Requests:** `POST https://slack.com/api/<method>` with
  `Content-Type: application/x-www-form-urlencoded` and the token as a **form body
  parameter** (`token=<token>`). NEVER use an Authorization header (Slack's CORS preflight
  rejects it) and NEVER use a JSON body (these Slack methods reject JSON bodies).
- **Pre-check:** method `auth.test` → JSON `{"ok":true, "team":..., "user":..., "url":...}`.
  Show team + user. `{"ok":false,"error":"invalid_auth"}` → dead.
- **Revoke:** method `auth.revoke` → `{"ok":true,"revoked":true}` on success. Optional
  documented dry-run: include `test=1`.
- **Post-check:** `auth.test` again → `invalid_auth` or `token_revoked` confirms revoked.
  - Reference: https://docs.slack.dev/reference/methods/auth.revoke/

### 3. GitLab

- **Detect:** token starts with `glpat-`. v1 supports gitlab.com only (self-hosted
  instances are out of scope; note this in the UI if a custom instance could be pasted).
- **Auth mechanism:** pass the token as the `private_token` **query parameter** on all
  calls (GitLab accepts this; it avoids custom-header preflight issues).
- **Pre-check:** `GET https://gitlab.com/api/v4/personal_access_tokens/self?private_token=<token>`
  → `200` with token metadata (scopes, expiry, last used). `401` → dead.
- **Revoke:** `DELETE https://gitlab.com/api/v4/personal_access_tokens/self?private_token=<token>`
  → `204` on success. NOTE: the DELETE method always triggers a CORS preflight; GitLab
  returns `Access-Control-Allow-Origin: *` and permits DELETE in production, but if the
  preflight fails, show a specific error ("browser blocked the GitLab revoke — try the
  GitLab UI: User Settings → Access Tokens") instead of a generic failure.
- **Post-check:** repeat the GET; `401` confirms revoked.
  - Reference: https://docs.gitlab.com/api/personal_access_tokens/

### 4. Dropbox

- **Detect:** Dropbox OAuth tokens are not reliably pattern-matchable. Auto-detect is best
  effort only; rely on the manual dropdown.
- **Requests:** `POST https://api.dropboxapi.com/<endpoint>` with
  `Authorization: Bearer <token>` and no body for these three endpoints (Dropbox accepts
  empty bodies on them; its CORS allows the Authorization header — its official SDK runs
  in browsers).
- **Pre-check:** `POST /2/users/get_current_account` → `200` with account name/email.
  `401` → dead.
- **Revoke:** `POST /2/auth/token/revoke` → `200` on success. This revokes only the
  token used to make the call.
- **Post-check:** repeat get_current_account; `401` confirms revoked.

### 5. Google (OAuth access/refresh tokens only)

- **Detect:** heuristics only (refresh tokens typically start `1//`; older access tokens
  `ya29.`). Prefer manual dropdown selection.
- **Revoke:** `POST https://oauth2.googleapis.com/revoke` with
  `Content-Type: application/x-www-form-urlencoded` and body `token=<token>`, sent via
  `fetch(..., { mode: 'no-cors' })`. This endpoint does NOT support CORS — the response is
  always opaque, so the revoke cannot be confirmed directly. Report as
  `SENT_UNVERIFIED` unless the post-check below can verify.
  - Reference: https://developers.google.com/identity/protocols/oauth2/javascript-implicit-flow
- **Post-check (access tokens only):**
  `GET https://oauth2.googleapis.com/tokeninfo?access_token=<token>`
  → `200` with scope/expiry before revoke, `400` after. This differential confirms the kill.
- **Refresh tokens:** cannot be verified from a browser. UI must say:
  "Revocation request sent — Google does not allow browsers to confirm this. If revocation
  failed, revoke via https://myaccount.google.com/permissions."
- Note: the token goes in the query string for the tokeninfo call (unavoidable — that's
  how that endpoint works). The revoke call must use the form body, not the query string.

## Explicitly out of scope (do not add)

- **Twilio** (auth-token rotation): Twilio's REST API does not permit browser calls
  (CORS preflight fails) — a static page cannot do it.
- **npm** (token revoke): registry CORS is unreliable on authenticated DELETE endpoints
  and 2FA accounts reject token-management calls for bypass-2FA tokens.
- **AWS, GCP (service account keys, AIza API keys), Azure, Stripe, OpenAI, Anthropic,
  SendGrid, Telegram**: none of these have a self-revoke endpoint — they require a
  separate authorized credential, which a static page cannot hold. Do not attempt
  workarounds.

## File layout

```
index.html      # structure + CSP/referrer meta + trust footer
style.css
app.js          # all logic: detection table, provider modules, state machine
```

`app.js` should be organized as one module per provider implementing a shared interface:
`{ detect(token) → bool, preCheck(token), revoke(token), postCheck(token) }`, plus a
shared `reportState(status, detail)` renderer. Comment the security-relevant lines
(especially the CSP rationale and the "do not modify request shapes" notes) — auditability
is a feature of this project.

## README.md (also write this)

Explain: what the page does, the threat model ("you are pasting a live secret into a
hosted page — here's why that's OK here: static, zero deps, CSP-allowlisted endpoints,
view source"), how to verify it (repo is the source of truth, GitHub Pages serves exactly
what's committed), and the identity-confirmation flow.

## Acceptance criteria

1. Paste a live Slack bot token → identity shown (team/user) → revoke → post-check
   confirms `token_revoked`. All without leaving the page.
2. Paste a GitHub PAT → identity + scopes shown → revoke → `202` + post-check `401`.
3. Paste an already-revoked token → "already invalid — nothing to do", no revoke call sent.
4. CSP blocks any fetch to a non-allowlisted origin (verify by attempting one in devtools
   and observing the block).
5. No token ever appears in localStorage, cookies, or console output.
6. Google refresh-token flow shows `SENT_UNVERIFIED` with the honest messaging above.
7. Network error / timeout on any call → clean error state, no silent failure, no token
   displayed in the error.