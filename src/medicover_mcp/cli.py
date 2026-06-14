"""`medicover-auth` — one-time interactive bootstrap (NOT an MCP tool).

`medicover-auth login` performs username+password login, prompts for the SMS code, completes
the OAuth/2FA chain, and persists the resulting refresh token to the local credential store
so the MCP server can run unattended thereafter.

Credentials are read from MEDICOVER_USERNAME / MEDICOVER_PASSWORD if set, else prompted. They
are never written to disk or logged — only the resulting refresh token is persisted.
"""

from __future__ import annotations

import argparse
import getpass
import sys

import httpx

from . import config
from .auth import AuthError, LoginFlow, jwt_expiry
from .store import CredentialStore, StoredCredentials


def _eprint(*a):
    print(*a, file=sys.stderr)


def cmd_login(settings: config.Settings) -> int:
    store = CredentialStore(settings.store_path)
    username = settings.username or input("Medicover username (MRN / login): ").strip()
    password = settings.password or getpass.getpass("Medicover password: ")
    if not username or not password:
        _eprint("error: username and password are required")
        return 2

    flow = LoginFlow()
    try:
        flow.begin()
        needs_mfa = flow.submit_password(username, password)
        if needs_mfa:
            flow.request_mfa()  # triggers the SMS
            _eprint("An SMS code was sent to the phone on file.")
            code = input("Enter the SMS code: ").strip()
            flow.submit_mfa(code)
        else:
            _eprint("Trusted device recognised — no SMS code required.")
        result = flow.finish()
    except AuthError as exc:
        _eprint(f"Login failed: {exc}")
        return 1
    except httpx.HTTPError as exc:
        _eprint(f"Network error talking to Medicover: {exc}")
        return 1

    holder_mrn = _safe_int(username)
    store.save(
        StoredCredentials(
            refresh_token=result.tokens.refresh_token or "",
            device_id=result.device_id,
            holder_mrn=holder_mrn,
        )
    )
    if not result.tokens.refresh_token:
        _eprint("warning: no refresh token returned; unattended runtime will not work")
        return 1

    exp = jwt_expiry(result.tokens.access_token)
    _eprint(f"Login successful. Credentials saved to {store.path} (mode 0600).")
    if exp:
        _eprint("Access tokens are short-lived (~3 min); the server refreshes them silently.")
    return 0


def cmd_status(settings: config.Settings) -> int:
    store = CredentialStore(settings.store_path)
    if not store.exists():
        _eprint(f"No credentials at {store.path}. Run `medicover-auth login`.")
        return 1
    try:
        creds = store.load()
    except Exception as exc:  # noqa: BLE001
        _eprint(f"Credential store unreadable: {exc}")
        return 1
    _eprint(f"Credential store: {store.path}")
    _eprint(f"  account holder MRN: {creds.holder_mrn or 'unknown'}")
    _eprint(f"  device id:          {creds.device_id}")
    _eprint("  refresh token:      present (value not shown)")
    return 0


def cmd_logout(settings: config.Settings) -> int:
    store = CredentialStore(settings.store_path)
    if store.exists():
        store.path.unlink()
        _eprint(f"Removed {store.path}.")
    else:
        _eprint("Nothing to remove.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="medicover-auth", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("login", help="interactive login + SMS 2FA; persist the refresh token")
    sub.add_parser("status", help="show whether credentials are stored (no secrets shown)")
    sub.add_parser("logout", help="delete the stored credentials")
    args = parser.parse_args(argv)

    settings = config.Settings.from_env()
    if args.command == "login":
        return cmd_login(settings)
    if args.command == "status":
        return cmd_status(settings)
    if args.command == "logout":
        return cmd_logout(settings)
    parser.print_help()
    return 2


def _safe_int(v: str) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


if __name__ == "__main__":
    raise SystemExit(main())
