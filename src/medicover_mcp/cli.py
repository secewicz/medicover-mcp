"""`medicover-auth` — one-time interactive bootstrap (NOT an MCP tool).

`medicover-auth login` performs username+password login, prompts for the SMS code, completes
the OAuth/2FA chain, and persists the resulting refresh token to the local credential store
so the MCP server can run unattended thereafter.

Credentials are read from MEDICOVER_USERNAME / MEDICOVER_PASSWORD if set, else prompted. They
are never written to disk or logged — only the resulting refresh token is persisted.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import sys

import httpx

from . import auth, config
from .auth import AuthError, LoginFlow, jwt_expiry, new_device_id
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


def _extract_refresh_token(pasted: str) -> str | None:
    """Accept either a raw refresh token or the browser's `oidc.user:...` JSON blob."""
    pasted = pasted.strip()
    if not pasted:
        return None
    if pasted.startswith("{"):
        try:
            return json.loads(pasted).get("refresh_token")
        except ValueError:
            return None
    return pasted


def _jwt_sub(token: str) -> int | None:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        sub = json.loads(base64.urlsafe_b64decode(payload)).get("sub")
        return int(sub) if sub is not None else None
    except Exception:
        return None


def cmd_set_token(settings: config.Settings, from_stdin: bool = False) -> int:
    """Bootstrap by pasting a refresh token captured from a logged-in browser session.

    Get it from your browser's devtools while logged in to online24.medicover.pl:
    Application -> Local/Session Storage -> the `oidc.user:...` entry -> copy `refresh_token`
    (or paste the whole JSON value). NB: the refresh token rotates on use, so do this promptly.
    """
    store = CredentialStore(settings.store_path)
    if from_stdin:
        # Fork change: tools/medicover_browser_login.py pipes the token in, so nobody has to paste it against the clock.
        rt = _extract_refresh_token(sys.stdin.readline())
    else:
        _eprint(
            "Paste your refresh token (or the whole `oidc.user:...` JSON from the browser's\n"
            "Local/Session Storage), then press Enter. Input is hidden:"
        )
        rt = _extract_refresh_token(getpass.getpass(""))
    if not rt:
        _eprint("error: no refresh token found in input")
        return 2

    # Validate immediately by refreshing once. This confirms the token, captures the ROTATED
    # token (so we own the chain henceforth), and derives the holder MRN.
    try:
        with httpx.Client(
            timeout=settings.request_timeout, headers={"User-Agent": config.USER_AGENT}
        ) as c:
            resp = c.post(
                config.TOKEN_ENDPOINT,
                data=auth.build_refresh_request(rt),
                headers={"Accept": "application/json"},
            )
        tokens = auth.parse_token_response(resp)
    except AuthError as exc:
        _eprint(f"Refresh token rejected: {exc}")
        _eprint(
            "It may have already rotated in your browser (the SPA refreshes every few "
            "minutes). Grab a fresh one and paste it promptly."
        )
        return 1
    except httpx.HTTPError as exc:
        _eprint(f"Network error talking to Medicover: {exc}")
        return 1

    if not tokens.refresh_token:
        _eprint("warning: no rotated refresh token returned; unattended runtime will not work")
        return 1
    holder_mrn = _jwt_sub(tokens.access_token)
    store.save(
        StoredCredentials(
            refresh_token=tokens.refresh_token,
            device_id=new_device_id(),
            holder_mrn=holder_mrn,
        )
    )
    _eprint(f"Saved to {store.path} (mode 0600). Authenticated as MRN {holder_mrn}.")
    _eprint(
        "Note: the refresh token rotated to this tool, so your browser tab will be logged "
        "out on its next refresh — that's expected."
    )
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
    st = sub.add_parser(
        "set-token",
        help="bootstrap by pasting a refresh token from a logged-in browser session",
    )
    st.add_argument("--stdin", action="store_true", help="read the token from the first line of stdin instead of prompting")
    sub.add_parser("status", help="show whether credentials are stored (no secrets shown)")
    sub.add_parser("logout", help="delete the stored credentials")
    args = parser.parse_args(argv)

    settings = config.Settings.from_env()
    if args.command == "login":
        return cmd_login(settings)
    if args.command == "set-token":
        return cmd_set_token(settings, from_stdin=args.stdin)
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
