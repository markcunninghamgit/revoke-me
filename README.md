# revoke.me

A single-page, fully static website for incident response on leaked credentials. Paste a
leaked secret/token; the page identifies the provider, shows you *whose* credential it is
(login, team, account), and revokes the token directly from your browser against the
provider's own self-revoke endpoint.

**No backend. No server. No database. No logging.** This is static code, hosted as-is:
three files (HTML, CSS, JS) served by GitHub Pages with no build step and no runtime.
Everything runs client-side against the provider's public API. If you don't trust this
host, the site is trivially self-hostable — see [Self-hosting](#self-hosting-with-docker).

## License

Released under the [Unlicense](LICENSE) — dedicated to the public domain. Copy it, modify
it, sell it, run it anywhere, no restrictions, no attribution required.

## ⚠️ Status: draft, untested

This project is a **draft that has not been tested yet**. It was written entirely with
Mistral AI (Vibe Code) — every line of the site, the Python CLI, the CI pipeline, and the
Docker packaging was AI-generated. Automated checks pass (syntax, unit tests with mocked
network, CI builds, container smoke tests), but **no revocation has been verified
end-to-end against a real, live token**.

Until this software has been exercised against real credentials, treat every reported
outcome — especially `CONFIRMED_REVOKED` — with suspicion, and verify revocation with the
provider directly (their web UI or API) before considering a credential killed.

## What it does

1. **Detect** the provider from the token pattern (GitHub `ghp_…`, Slack `xoxb-…`,
   GitLab `glpat-…`, Google heuristics), with a manual dropdown fallback for token types
   that aren't reliably pattern-matchable (Dropbox).
2. **Pre-check** (whoami/info call): shows the compromised identity — login and scopes for
   GitHub, team and user for Slack, token metadata for GitLab, account name/email for
   Dropbox — and confirms the token is live. If it's already dead: "already invalid —
   nothing to do" and no revoke call is sent.
3. **Confirm**: identity info plus a single Revoke button. Nothing is auto-revoked on paste.
4. **Revoke** via the provider's endpoint.
5. **Post-check**: re-run the info call. Live-before + dead-after = `CONFIRMED_REVOKED`
   (with a 1-second retry to absorb propagation delay). Otherwise the page reports
   `SENT_UNVERIFIED` with honest messaging rather than pretending.

## Threat model — why pasting a live secret into a hosted page is OK here

You are pasting a live secret into a hosted page. That should make you nervous, so here is
exactly why it's safe here:

- **The repo is the source of truth.** GitHub Pages serves *exactly* what's committed to
  this repository — there is no build step, no server-side rendering, no runtime
  dependency resolution. What you view-source is what runs.
- **Zero external dependencies.** No CDN, no web fonts, no analytics, no third-party
  scripts, no images from other origins. Plain HTML/CSS/JS.
- **Mechanical CSP enforcement.** The page's Content-Security-Policy allowlists
  `connect-src` to exactly five provider API origins
  (api.github.com, slack.com, oauth2.googleapis.com, api.dropboxapi.com, gitlab.com).
  The browser makes it *technically impossible* for this page to send the secret anywhere
  else. Verify it yourself: try `fetch('https://example.com')` in devtools on the hosted
  page and watch it get blocked.
- **No persistence.** The token lives in one JavaScript variable. No localStorage, no
  sessionStorage, no cookies. It is wiped on page unload, and a **Wipe** button clears it
  on demand.
- **No logging.** The token is never written to the console, error messages, or the URL.
- **View source — nothing here phones home.**

## Supported providers

| Provider | Token types | Confirmable? |
|-----------|-------------|--------------|
| GitHub | `ghp_`, `gho_`, `ghu_`, `ghr_`, `github_pat_` | Yes — post-check `401` |
| Slack | `xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-`, `xapps-` | Yes — `token_revoked` |
| GitLab | `glpat-` (gitlab.com only; self-hosted out of scope) | Yes — post-check `401` |
| Dropbox | manual dropdown (not pattern-matchable) | Yes — post-check `401` |
| Google | OAuth access (`ya29.`) / refresh (`1//`) tokens | Access: via `tokeninfo`; Refresh: `SENT_UNVERIFIED` |

Twilio, npm, AWS, Azure, Stripe, OpenAI, and others are intentionally out of scope — their
APIs either don't permit browser calls (CORS preflight fails) or have no self-revoke
endpoint (revocation requires a separate authorized credential).

## Python CLI (`revoke-me`)

The same logic as a pip-installable command-line tool — for when you'd rather not touch a
browser (or any hosted page) with a live token. The token is read via a hidden
`getpass` prompt: it never lands in shell history, is never logged, and only ever goes to
the provider's own revoke/info endpoints.

```sh
git clone https://github.com/markcunninghamgit/revoke-me
cd revoke-me
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.txt   # hash-pinned deps
.venv/bin/pip install -e . --no-deps
.venv/bin/revoke-me            # or: .venv/bin/revoke-me --provider dropbox
```

Options: `--provider` forces a provider (Dropbox tokens aren't pattern-matchable),
`--no-revoke` only inspects the token and shows the identity, `--yes` skips the
confirmation prompt. Outcomes match the website: `ALREADY_DEAD`, `CONFIRMED_REVOKED`,
`SENT_UNVERIFIED`, or `FAILED`.

Built sdist and wheel artifacts are attached to each GitHub release, so you can also
`pip install revoke-me --find-links <release-url>` or upload the package to a private
index. The packaging layout (`src/`, `pyproject.toml`, console-script entry point) follows
current PyPI conventions, so it can be submitted to PyPI as-is.

## The identity-confirmation flow

The point of the pre-check is that you shouldn't revoke blind. Before anything is sent,
the page shows who the credential belongs to: the GitHub login and its scopes, the Slack
team and user, the GitLab token name/scopes/expiry, the Dropbox account email. If the
token is already dead, the page tells you so and sends nothing. Only after you see the
identity and press Revoke does the revoke call go out — followed by a post-check that
turns "the API accepted it" into "the token is confirmed dead".

## Hosting

GitHub Pages serves the repository root as-is. `index.html`, `style.css`, `app.js` —
that's the whole site; the repo is the source of truth.

## Self-hosting with Docker

Because the site is pure static files, a self-host needs nothing but a web server. A
minimal Dockerfile and compose file are included (nginx:alpine serving the three files,
read-only container):

```sh
docker compose up --build -d   # → http://localhost:8080
```

or without compose:

```sh
docker build -t revoke-me .
docker run -d -p 8080:80 --read-only --name revoke-me revoke-me
```

Or pull the CI-published image straight from GHCR (built on every push to main):

```sh
docker run -d -p 8080:80 --read-only ghcr.io/MARKCUNNINGHAMGIT/revoke-me:latest
```

## CI

`.github/workflows/ci.yml` runs on every branch: syntax check, a security audit
(fails if storage or console APIs appear), CSP verification against the spec'd
origins, the smoke test, and a Docker build + container smoke test. On main it
also pushes the image to `ghcr.io/<owner>/revoke-me` (tags: `latest`, commit
SHA) and creates a GitHub release with the static site bundled as `site.zip`.

The nginx config serves only static files — no CGI, no proxying, nothing dynamic —
so the self-hosted instance is exactly as trustworthy as the hosted one: read the
30-odd lines of config, then verify the served files match the repo.

Even simpler: clone the repo and open `index.html` directly from disk. Everything
works from `file://` too — that's the whole point of a static site.
