#!/usr/bin/env python3
"""Unattended renewal of ONE account's Medicover login (ADR-085). Run by a timer on the hub as that account's own user.

Each run: (1) ask the account's own server instance, over loopback, whether the login works; if it does, there is nothing to do. (2) if
it does not, and the safety rules below allow it, log in once in a fresh headless Chrome with the account's password and trusted-device key
(from the environment, which systemd fills from a root-owned 0600 file that the deploy writes from SOPS), and store the session with
`medicover-auth set-session`. (3) verify that it worked.

SAFETY RULES, because a wrong password retried in a loop locks a real person out of their medical portal:
  * at most one browser login per 10 minutes and six per 24 hours;
  * a rejected password, or a request for the emailed code, BLOCKS the account (no more attempts) until the password or device key in
    SOPS changes (the block remembers a hash of them, never the values), or the login is delivered some other way and found alive;
  * three failures in a row (timeouts, crashes) block it for six hours.

EXIT CODES: 0 = alive, renewed, waiting out a limit, or the instance is not reachable (nothing to renew); 3 = blocked: the portal wants the
emailed code; 4 = blocked: the password was rejected; 5 = blocked: repeated failures. A non-zero exit leaves the systemd unit FAILED, which
the hub's check turns into the Kuma monitor `mcp-hub medicover renewal` going DOWN (and Slack). Nothing secret is printed.

    medicover_renew.py --account filip --port 9094 --state-file /var/lib/mcp-hub-medicover/filip/renewal.json
Environment: MEDICOVER_USERNAME, MEDICOVER_PASSWORD, MEDICOVER_DEVICE_KEY, MEDICOVER_STORE_PATH (and MEDICOVER_CHROME / MEDICOVER_CHROME_ARGS).
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

EXIT_CODE, EXIT_PASSWORD, EXIT_REPEATED = 3, 4, 5
MIN_GAP = 600                 # seconds between two browser logins
DAILY_MAX = 6                 # browser logins in any 24 hours
FAIL_BLOCK_AFTER = 3          # consecutive failures that are not a refusal
FAIL_BLOCK_SECONDS = 6 * 3600
BLOCK_EXIT = {"code": EXIT_CODE, "password": EXIT_PASSWORD, "repeated": EXIT_REPEATED}


def secret_hash(user: str, password: str, device_key: str) -> str:
    """Identifies WHICH credentials a block belongs to without storing them: a different password or key lifts the block."""
    return hashlib.sha256("\0".join((user, password, device_key)).encode()).hexdigest()[:16]


def load_state(path: Path) -> dict:
    try:
        d = json.loads(path.read_text())
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(path: Path, state: dict) -> None:
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(state, fh)
    os.replace(tmp, path)


def decide(state: dict, now: float, secret: str) -> tuple[str, str]:
    """('blocked', reason) | ('wait', why) | ('go', ''). May edit state (lifting a block that no longer applies)."""
    blocked = state.get("blocked")
    if blocked:
        reason = blocked.get("reason")
        if reason in ("password", "code") and blocked.get("secret") != secret:
            state["blocked"] = None                      # the password or key in SOPS changed: try again
        elif reason == "repeated" and now >= blocked.get("until", 0):
            state["blocked"] = None
        else:
            return "blocked", reason
    attempts = [t for t in state.get("attempts", []) if now - t < 86400]
    state["attempts"] = attempts
    if attempts and now - attempts[-1] < MIN_GAP:
        return "wait", "last browser login was under 10 minutes ago"
    if len(attempts) >= DAILY_MAX:
        return "wait", "six browser logins in the last 24 hours"
    return "go", ""


def apply_result(state: dict, status: str, now: float, secret: str) -> None:
    if status == "ok":
        state["failures"], state["blocked"] = 0, None
    elif status in ("rejected", "code"):
        state["blocked"] = {"reason": "password" if status == "rejected" else "code", "secret": secret, "at": now}
    else:
        state["failures"] = state.get("failures", 0) + 1
        if state["failures"] >= FAIL_BLOCK_AFTER:
            state["blocked"] = {"reason": "repeated", "until": now + FAIL_BLOCK_SECONDS, "at": now}


async def alive(port: int) -> bool | None:
    """True: the instance serves list_patients. False: it answers with an error. None: it is not reachable at all."""
    from mcp import ClientSession
    from mcp.client.sse import sse_client
    try:
        async with asyncio.timeout(60):
            async with sse_client(f"http://127.0.0.1:{port}/sse") as (r, w):
                async with ClientSession(r, w) as s:
                    await s.initialize()
                    await s.list_tools()
                    res = await s.call_tool("list_patients", {})
        return bool(not res.isError and res.content)
    except Exception:
        return None


def deliver(session: dict, auth_bin: str, store_path: str) -> bool:
    done = subprocess.run([auth_bin, "set-session"], input=json.dumps(session), text=True, capture_output=True,
                          env=dict(os.environ, MEDICOVER_STORE_PATH=store_path))
    return done.returncode == 0


def say(account: str, message: str) -> None:
    print(f"renew {account}: {message}", flush=True)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--account", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--state-file", required=True)
    p.add_argument("--auth-bin", default="medicover-auth")
    p.add_argument("--timeout", type=int, default=150)
    args = p.parse_args(argv)

    user, password, dk = (os.environ.get(k, "") for k in ("MEDICOVER_USERNAME", "MEDICOVER_PASSWORD", "MEDICOVER_DEVICE_KEY"))
    store = os.environ.get("MEDICOVER_STORE_PATH", "")
    if not (user and password and store):
        say(args.account, "MEDICOVER_USERNAME / MEDICOVER_PASSWORD / MEDICOVER_STORE_PATH are not set")
        return 2
    path, now = Path(args.state_file), time.time()
    state, secret = load_state(path), secret_hash(user, password, dk)

    is_alive = asyncio.run(alive(args.port))
    if is_alive is None:
        say(args.account, "the instance is not reachable; nothing to renew")
        return 0
    if is_alive:
        if state.get("blocked") or state.get("failures"):
            state["blocked"], state["failures"] = None, 0
            save_state(path, state)
        say(args.account, "login alive")
        return 0

    verdict, why = decide(state, now, secret)
    if verdict == "blocked":
        save_state(path, state)
        say(args.account, f"BLOCKED ({why}); no more attempts until the password/key in SOPS changes" + (" or six hours pass" if why == "repeated" else ""))
        return BLOCK_EXIT[why]
    if verdict == "wait":
        save_state(path, state)
        say(args.account, f"login dead, waiting: {why}")
        return 0

    state.setdefault("attempts", []).append(now)
    save_state(path, state)                        # the attempt counts even if this process dies mid-login
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from medicover_headless_login import run_login
    status, session = run_login(user, password, dk or None, args.timeout, say=lambda m: None)
    password = ""                                   # noqa: F841
    if status == "ok" and session and deliver(session, args.auth_bin, store):
        again = asyncio.run(alive(args.port))
        if again:
            apply_result(state, "ok", now, secret)
            save_state(path, state)
            say(args.account, "login renewed")
            return 0
        status = "timeout"                          # delivered but not working: counts as a plain failure
    apply_result(state, status, now, secret)
    save_state(path, state)
    blocked = state.get("blocked")
    say(args.account, f"renewal failed ({status})" + (f"; BLOCKED ({blocked['reason']})" if blocked else "; will retry"))
    return BLOCK_EXIT[blocked["reason"]] if blocked else 0


if __name__ == "__main__":
    sys.exit(main())
