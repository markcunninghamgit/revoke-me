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

    # Pre-check
    live, identity, err = providers.pre_check(provider, token, session)
    if err:
        print("PRE-CHECK ERROR: " + err)
        return 2
    if live is False:
        print("ALREADY_DEAD: token is already invalid — nothing to do")
        return 0
    if live is None:
        print("no readable pre-check for this provider/token type; continuing")
    else:
        print("token is LIVE and belongs to:")
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
    sent, _detail, err = providers.revoke(provider, token, session)
    if err or not sent:
        print("FAILED: " + (err or "revoke was not accepted"))
        return 2

    # Post-check (1s propagation retry, same as the website)
    import time
    time.sleep(1)
    if providers.post_check(provider, token, session):
        print("CONFIRMED_REVOKED: token was live before and is dead after revoke")
        return 0
    print(
        "SENT_UNVERIFIED: revoke was accepted, but the post-check could not "
        "confirm" + (" (Google refresh tokens cannot be verified from a client)" if provider == "google" else "")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
