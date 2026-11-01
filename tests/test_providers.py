"""Unit tests for revoke-me provider logic (no network access)."""

import sys
from unittest import mock

sys.path.insert(0, "src")

from revoke_me import providers  # noqa: E402


def _resp(status=200, json_body=None, text=None, headers=None):
    r = mock.Mock()
    r.status_code = status
    r.headers = headers or {}
    r.json.return_value = json_body or {}
    r.text = text if text is not None else ("" if json_body is None else "{}")
    return r


class FakeSession:
    def __init__(self):
        self.calls = []
        self.responses = []

    def _record(self, method, url, **kw):
        self.calls.append((method, url, kw))
        return self.responses.pop(0)

    def get(self, url, **kw):
        return self._record("GET", url, **kw)

    def post(self, url, **kw):
        return self._record("POST", url, **kw)

    def delete(self, url, **kw):
        return self._record("DELETE", url, **kw)


def test_detect():
    assert providers.detect("ghp_abc") == "github"
    assert providers.detect("github_pat_X") == "github"
    assert providers.detect("xoxb-123") == "slack"
    assert providers.detect("xapps-1") == "slack"
    assert providers.detect("glpat-xyz") == "gitlab"
    assert providers.detect("1//abc") == "google"
    assert providers.detect("ya29.abc") == "google"
    assert providers.detect("sl.aBcD123") is None  # Dropbox: manual


def test_github_pre_check_live():
    s = FakeSession()
    s.responses = [_resp(200, {"login": "octo", "name": "Octo Cat"}, headers={"X-OAuth-Scopes": "repo"})]
    live, ident, err = providers.pre_check("github", "ghp_x", s)
    assert live is True and err is None
    assert "octo" in ident and "repo" in ident


def test_github_pre_check_dead():
    s = FakeSession()
    s.responses = [_resp(401)]
    live, ident, err = providers.pre_check("github", "ghp_x", s)
    assert live is False


def test_github_revoke_shape():
    """Revoke must be unauthenticated (no Authorization header) with JSON credentials."""
    s = FakeSession()
    s.responses = [_resp(202)]
    sent, _, err = providers.revoke("github", "ghp_x", s)
    assert sent is True
    method, url, kw = s.calls[0]
    assert method == "POST" and "credentials/revoke" in url
    assert kw["json"] == {"credentials": ["ghp_x"]}
    assert "Authorization" not in kw.get("headers", {})
    assert kw["headers"]["Accept"] == "application/vnd.github+json"


def test_slack_form_body_shape():
    """Slack must use form-encoded token parameter, never a JSON body."""
    s = FakeSession()
    s.responses = [_resp(200, {"ok": True, "revoked": True}, text='{"ok":true}')]
    sent, _, err = providers.revoke("slack", "xoxb-x", s)
    assert sent is True
    method, url, kw = s.calls[0]
    assert method == "POST" and "auth.revoke" in url
    assert kw["data"] == {"token": "xoxb-x"}
    assert "json" not in kw


def test_gitlab_query_param_shape():
    """GitLab token goes in the private_token query parameter."""
    s = FakeSession()
    s.responses = [_resp(204)]
    sent, _, err = providers.revoke("gitlab", "glpat-x", s)
    assert sent is True
    method, url, kw = s.calls[0]
    assert method == "DELETE" and "personal_access_tokens/self" in url
    assert kw["params"] == {"private_token": "glpat-x"}


def test_dropbox_bearer_shape():
    s = FakeSession()
    s.responses = [_resp(200)]
    sent, _, err = providers.revoke("dropbox", "sl.ABC", s)
    assert sent is True
    method, url, kw = s.calls[0]
    assert kw["headers"]["Authorization"] == "Bearer sl.ABC"


def test_google_form_body_shape():
    s = FakeSession()
    s.responses = [_resp(200)]
    sent, _, err = providers.revoke("google", "1//xyz", s)
    assert sent is True
    method, url, kw = s.calls[0]
    assert "oauth2.googleapis.com/revoke" in url
    assert kw["data"] == {"token": "1//xyz"}


def test_post_check_confirms_dead():
    s = FakeSession()
    s.responses = [_resp(401)]
    assert providers.post_check("github", "ghp_x", s) is True


def test_post_check_google_refresh_never_confirms():
    s = FakeSession()
    assert providers.post_check("google", "1//xyz", s) is False
    assert s.calls == []  # no request even made


def test_github_rate_limit_error():
    s = FakeSession()
    s.responses = [_resp(429)]
    sent, _, err = providers.revoke("github", "ghp_x", s)
    assert sent is False and "rate limit" in err
