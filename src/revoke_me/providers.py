"""Provider definitions: detection, pre-check, revoke, post-check.

Request shapes mirror the website exactly and must not be "cleaned up":
every content type, header, and parameter placement is dictated by the
provider's API contract (not CORS here, but correctness).
"""

TIMEOUT = 15

# Token regex per provider, tried in order.
DETECTORS = {
    "github": r"^(ghp_|gho_|ghu_|ghr_|github_pat_)",
    "slack": r"^(xoxb-|xoxp-|xoxa-|xoxr-|xoxs-|xapps-)",
    "gitlab": r"^glpat-",
    "google": r"^(1//|ya29\.)",
    # Dropbox tokens are not reliably pattern-matchable: manual choice.
}

PROVIDERS = ["github", "slack", "gitlab", "dropbox", "google"]


def detect(token):
    """Return the detected provider id, or None."""
    import re
    for pid, pattern in DETECTORS.items():
        if re.match(pattern, token):
            return pid
    return None


def pre_check(provider, token, session):
    """Return (live, identity, error). live is True/False/None (unknown)."""
    if provider == "github":
        r = session.get(
            "https://api.github.com/user",
            headers={
                "Authorization": "Bearer " + token,
                "Accept": "application/vnd.github+json",
            },
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            scopes = r.headers.get("X-OAuth-Scopes", "")
            login = r.json().get("login", "(unknown login)")
            name = r.json().get("name") or ""
            ident = "login: " + login + ((" (" + name + ")") if name else "")
            if scopes:
                ident += "\nscopes: " + scopes
            return True, ident, None
        if r.status_code == 401:
            return False, "", None
        return None, "", "GitHub pre-check: HTTP %d — token may be fine but the request was blocked or rate-limited" % r.status_code
    if provider == "slack":
        r = session.post(
            "https://slack.com/api/auth.test",
            data={"token": token},
            timeout=TIMEOUT,
        )
        body = r.json() if r.text else {}
        if body.get("ok"):
            return True, "team: %s\nuser: %s" % (body.get("team", "(unknown)"), body.get("user", "(unknown)")), None
        if body.get("error") in ("invalid_auth", "token_revoked"):
            return False, "", None
        return None, "", "Slack pre-check: %s" % body.get("error", "HTTP %d" % r.status_code)
    if provider == "gitlab":
        r = session.get(
            "https://gitlab.com/api/v4/personal_access_tokens/self",
            params={"private_token": token},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            j = r.json()
            ident = "name: %s\nscopes: %s\nexpires: %s" % (
                j.get("name", "(unknown)"),
                ", ".join(j.get("scopes", [])) or "(unknown)",
                j.get("expires_at") or "(none)",
            )
            return True, ident, None
        if r.status_code == 401:
            return False, "", None
        return None, "", "GitLab pre-check: HTTP %d" % r.status_code
    if provider == "dropbox":
        r = session.post(
            "https://api.dropboxapi.com/2/users/get_current_account",
            headers={"Authorization": "Bearer " + token},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            j = r.json()
            return True, "account: %s\nemail: %s" % (
                (j.get("name") or {}).get("display_name", "(unknown)"),
                j.get("email", "(unknown)"),
            ), None
        if r.status_code == 401:
            return False, "", None
        return None, "", "Dropbox pre-check: HTTP %d" % r.status_code
    if provider == "google":
        # Access tokens can be inspected via tokeninfo; refresh tokens cannot.
        if token.startswith("ya29."):
            r = session.get(
                "https://oauth2.googleapis.com/tokeninfo",
                params={"access_token": token},
                timeout=TIMEOUT,
            )
            if r.status_code == 200:
                j = r.json()
                return True, "scope: %s\nexpires_in: %s" % (j.get("scope", "(unknown)"), j.get("expires_in", "(unknown)")), None
            if r.status_code in (400, 401):
                return False, "", None
            return None, "", "Google pre-check: HTTP %d" % r.status_code
        return None, "", None
    return None, "", "unknown provider"


def revoke(provider, token, session):
    """Send the revoke. Return (sent, detail, error)."""
    if provider == "github":
        # Unauthenticated endpoint ONLY: no Authorization header.
        r = session.post(
            "https://api.github.com/credentials/revoke",
            headers={
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
            },
            json={"credentials": [token]},
            timeout=TIMEOUT,
        )
        if r.status_code == 202:
            return True, "", None
        if r.status_code in (422, 429):
            return False, "", "GitHub revoke: HTTP %d — rate limit (60/hour unauthenticated) or malformed credentials" % r.status_code
        return False, "", "GitHub revoke: HTTP %d" % r.status_code
    if provider == "slack":
        r = session.post(
            "https://slack.com/api/auth.revoke",
            data={"token": token},
            timeout=TIMEOUT,
        )
        body = r.json() if r.text else {}
        if body.get("ok") and body.get("revoked"):
            return True, "", None
        if body.get("ok") and body.get("revoked") is False:
            return False, "", "Slack reports the token was already revoked"
        return False, "", "Slack revoke: %s" % body.get("error", "HTTP %d" % r.status_code)
    if provider == "gitlab":
        r = session.delete(
            "https://gitlab.com/api/v4/personal_access_tokens/self",
            params={"private_token": token},
            timeout=TIMEOUT,
        )
        if r.status_code == 204:
            return True, "", None
        return False, "", "GitLab revoke: HTTP %d" % r.status_code
    if provider == "dropbox":
        r = session.post(
            "https://api.dropboxapi.com/2/auth/token/revoke",
            headers={"Authorization": "Bearer " + token},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return True, "", None
        return False, "", "Dropbox revoke: HTTP %d" % r.status_code
    if provider == "google":
        r = session.post(
            "https://oauth2.googleapis.com/revoke",
            data={"token": token},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return True, "", None
        if r.status_code == 400:
            return False, "", "Google revoke: HTTP 400 — token already invalid or malformed"
        return False, "", "Google revoke: HTTP %d" % r.status_code
    return False, "", "unknown provider"


def post_check(provider, token, session):
    """Return True if the token is confirmed dead, False otherwise."""
    if provider == "google" and not token.startswith("ya29."):
        return False  # refresh tokens cannot be verified from a client
    live, _ident, _err = pre_check(provider, token, session)
    return live is False
