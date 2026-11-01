"""CLI-level tests: argument handling and flow outcomes (mocked network)."""

import sys
from unittest import mock

sys.path.insert(0, "src")

import pytest  # noqa: E402

from revoke_me import cli  # noqa: E402
from revoke_me import providers  # noqa: E402


def _patch_providers(monkeypatch, live, rev_sent, post_dead, pre_err=None):
    monkeypatch.setattr(cli.providers, "pre_check", lambda p, t, s: (live, "identity-x", pre_err))
    monkeypatch.setattr(cli.providers, "revoke", lambda p, t, s: (rev_sent, "", None))
    monkeypatch.setattr(cli.providers, "post_check", lambda p, t, s: post_dead)
    monkeypatch.setattr(cli.providers, "detect", lambda t: "github")


def run_cli(monkeypatch, argv, stdin_token, stdin_answer=""):
    monkeypatch.setattr("getpass.getpass", lambda *a: stdin_token)
    monkeypatch.setattr("builtins.input", lambda *a: stdin_answer)
    with mock.patch("requests.Session") as sess:
        s = sess.return_value
        s.headers = {}
        with mock.patch("time.sleep"):
            return cli.main(argv)


def test_no_token_aborts(monkeypatch, capsys):
    assert run_cli(monkeypatch, [], "") == 1


def test_unknown_provider_aborts(monkeypatch):
    monkeypatch.setattr(cli.providers, "detect", lambda t: None)
    assert run_cli(monkeypatch, [], "totally-unknown-token") == 1


def test_already_dead(monkeypatch, capsys):
    _patch_providers(monkeypatch, live=False, rev_sent=False, post_dead=False)
    assert run_cli(monkeypatch, ["--yes"], "ghp_x") == 0
    assert "ALREADY_DEAD" in capsys.readouterr().out


def test_confirmed_revoked(monkeypatch, capsys):
    _patch_providers(monkeypatch, live=True, rev_sent=True, post_dead=True)
    assert run_cli(monkeypatch, ["--yes"], "ghp_x") == 0
    assert "CONFIRMED_REVOKED" in capsys.readouterr().out


def test_sent_unverified(monkeypatch, capsys):
    _patch_providers(monkeypatch, live=True, rev_sent=True, post_dead=False)
    assert run_cli(monkeypatch, ["--yes"], "ghp_x") == 0
    assert "SENT_UNVERIFIED" in capsys.readouterr().out


def test_abort_declines_confirm(monkeypatch, capsys):
    _patch_providers(monkeypatch, live=True, rev_sent=True, post_dead=True)
    assert run_cli(monkeypatch, [], "ghp_x", stdin_answer="n") == 1
    assert "aborted" in capsys.readouterr().out


def test_no_revoke_flag(monkeypatch, capsys):
    _patch_providers(monkeypatch, live=True, rev_sent=True, post_dead=True)
    assert run_cli(monkeypatch, ["--no-revoke"], "ghp_x") == 0
    out = capsys.readouterr().out
    assert "not revoking" in out and "LIVE" in out
