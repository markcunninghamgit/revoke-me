"""revoke-me CLI: detect, verify, and revoke a leaked token.

The token is read via getpass (hidden input, never in shell history) and
is held only in a local variable for the process lifetime.
"""

import argparse
import getpass
import sys

import requests

from . import providers


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="revoke-me",
        description="Revoke a leaked token directly with the provider.",
    )
    parser.add_argument(
        "--provider",
        choices=providers.PROVIDERS,
        help="force a provider (default: auto-detect; Dropbox requires --provider dropbox)",
    )
    parser.add_argument(
        "--yes", "-y",
        action="store_true",
        help="skip the confirmation prompt (non-interactive revoke)",
    )
    parser.add_argument(
        "--no-revoke",
        action="store_true",
        help="only run the pre-check and show the identity; never revoke",
    )
    args = parser.parse_args(argv)

    token = getpass.getpass("Token (input hidden): ")
    if not token.strip():
        print("no token entered; aborting")
        return 1
    token = token.strip()

    provider = args.provider or providers.detect(token)
    if provider is None:
        print(
            "could not auto-detect the provider; re-run with --provider "
            "(one of: " + ", ".join(providers.PROVIDERS) + ")"
        )
        return 1

    session = requests.Session()
    session.headers.update({"User-Agent": "revoke-me-cli"})

    # Pre-check: verify the token is LIVE before revoking, so a wrong
    # paste or an already-dead key is never mistaken for a successful kill.
    print("Checking token is live...")
    live, identity, err = providers.pre_check(provider, token, session)
    if err:
        print("PRE-CHECK ERROR: " + err)
        print("Could not verify the token is live — NOT revoking. Check the key or the endpoint status.")
        return 2
    if live is False:
        print("ALREADY_DEAD: token is already invalid — nothing to do.")
        print("No revoke was sent. If you expected this token to be live, you may have pasted")
        print("the wrong key, or it was revoked/expired before now.")
        return 0
    if live is None:
        print("WARNING: no readable liveness check for this token type; cannot verify before revoking.")
    else:
        print("Token is LIVE and belongs to:")
        print("  " + identity.replace("\n", "\n  "))

    if args.no_revoke:
        print("--no-revoke set; not revoking")
        return 0

    if not args.yes:
        answer = input("Revoke this token? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            print("aborted; nothing sent")
            return 1

    # Revoke
    print("Revoking...")
    sent, _detail, err = providers.revoke(provider, token, session)
    if err or not sent:
        print("FAILED: " + (err or "revoke was not accepted"))
        print("The token may still be live — verify manually before assuming it is dead.")
        return 2

    # Post-check (1s propagation retry, same as the website): confirm the
    # token is now dead; live-before + dead-after = actually revoked.
    print("Confirming dead...")
    import time
    time.sleep(1)
    if providers.post_check(provider, token, session):
        print("CONFIRMED_REVOKED: token was live before the revoke and is dead after it")
        return 0
    print(
        "SENT_UNVERIFIED: the revoke was accepted, but the post-check could not "
        "confirm the token is dead. It may still be live — verify manually" +
        (" (Google refresh tokens cannot be verified from a client)" if provider == "google" else "")
    )
    return 3


if __name__ == "__main__":
    sys.exit(main())
