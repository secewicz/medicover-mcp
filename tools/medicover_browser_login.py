# /// script
# requires-python = ">=3.11"
# dependencies = ["websockets>=13"]
# ///
"""Log in to Medicover in a REAL Chrome and hand the session to the server, with nothing to paste.

The portal's password step is guarded by something only a browser can satisfy, so a script cannot log in by itself (measured 25 Oct
2026: the portal accepts the password and then refuses a non-browser client). This tool lets Chrome do that part:

  1. start Google Chrome with its own profile directory (default ~/.medicover-chrome; kept between runs) and remote debugging on loopback;
  2. YOU log in to online24.medicover.pl in that window: password, the code Medicover sends, and "trust this device". If the profile's
     session is still valid the page signs itself in and you type nothing;
  3. the moment the page holds a refresh token, this tool reads it, REMOVES it from the browser's storage (so the page cannot refresh a
     token the server now owns, which the portal punishes by revoking the chain), closes Chrome, and delivers the token:
       --local  PATH   write it with `medicover-auth set-token --stdin` into this credential file (a local test), or
       --hub    HOST   run `medicover-auth set-token --stdin` on the hub as the account's service user over ssh.

The token is never printed, never put on a command line and never written to disk by this tool; it goes to the child process's stdin.

    uv run tools/medicover_browser_login.py --local /tmp/creds.json
    uv run tools/medicover_browser_login.py --hub root@192.168.7.119 --key ~/.ssh/homelab_ed25519 --account filip
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from websockets.sync.client import connect

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
START_URL = "https://online24.medicover.pl/"
HOST = "online24.medicover.pl"
PORT = 9223

# Runs in the page. Returns {k, t} for the first oidc.user:* entry that holds a refresh token, else null.
FIND = """(() => { for (const st of [localStorage, sessionStorage]) { for (let i = 0; i < st.length; i++) {
  const k = st.key(i); if (k && k.startsWith('oidc.user:')) { try { const u = JSON.parse(st.getItem(k));
  if (u && u.refresh_token) return JSON.stringify({k: k, t: u.refresh_token}); } catch (e) {} } } } return null; })()"""
# Removes every oidc.user:* entry from both storages (the server owns the token from now on).
WIPE = """(() => { let n = 0; for (const st of [localStorage, sessionStorage]) { for (const k of Object.keys(st))
  { if (k.startsWith('oidc.user:')) { st.removeItem(k); n++; } } } return n; })()"""


def eprint(*a: object) -> None:
    print(*a, file=sys.stderr, flush=True)


def targets() -> list[dict]:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json", timeout=2) as r:
            return json.load(r)
    except Exception:
        return []


def evaluate(ws_url: str, expression: str):
    with connect(ws_url, max_size=2**22, open_timeout=3) as ws:
        ws.send(json.dumps({"id": 1, "method": "Runtime.evaluate", "params": {"expression": expression, "returnByValue": True}}))
        while True:
            msg = json.loads(ws.recv(timeout=5))
            if msg.get("id") == 1:
                return msg.get("result", {}).get("result", {}).get("value")


def close_chrome(chrome: subprocess.Popen) -> None:
    """Ask Chrome to quit through the debugging port (it flushes the profile, so the wiped token stays wiped), then make sure."""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json/version", timeout=2) as r:
            browser_ws = json.load(r)["webSocketDebuggerUrl"]
        with connect(browser_ws, open_timeout=3) as ws:
            ws.send(json.dumps({"id": 1, "method": "Browser.close"}))
    except Exception:
        pass
    try:
        chrome.wait(timeout=8)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(chrome.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass


def cdp_call(ws_url: str, method: str, params: dict | None = None):
    with connect(ws_url, max_size=2**23, open_timeout=3) as ws:
        ws.send(json.dumps({"id": 1, "method": method, "params": params or {}}))
        while True:
            msg = json.loads(ws.recv(timeout=5))
            if msg.get("id") == 1:
                return msg.get("result", {})


STORAGE_KEYS = "JSON.stringify({local: Object.keys(localStorage), session: Object.keys(sessionStorage)})"


def diagnose(label: str, ws_url: str) -> None:
    """--diagnose: what the profile REMEMBERS. Cookie names, domains, session-or-persistent and expiry; storage KEY NAMES. Never a value."""
    try:
        cookies = cdp_call(ws_url, "Network.getAllCookies").get("cookies", [])
        keys = json.loads(evaluate(ws_url, STORAGE_KEYS) or "{}")
    except Exception as exc:
        eprint(f"[diagnose {label}] failed: {type(exc).__name__}")
        return
    eprint(f"[diagnose {label}] {len(cookies)} cookies")
    for c in sorted(cookies, key=lambda c: (c.get("domain", ""), c.get("name", ""))):
        if "medicover" not in c.get("domain", ""):
            continue
        exp = "SESSION (dropped when Chrome quits)" if c.get("session") else time.strftime("expires %Y-%m-%d %H:%M UTC", time.gmtime(c.get("expires", 0)))
        eprint(f"   cookie {c.get('name','')[:40]:40} {c.get('domain',''):34} {exp}")
    eprint(f"   storage keys: local={[k[:60] for k in keys.get('local', [])]} session={[k[:60] for k in keys.get('session', [])]}")


def deliver(token: str, args: argparse.Namespace) -> int:
    if args.local:
        cmd = ["uv", "run", "--quiet", "medicover-auth", "set-token", "--stdin"]
        env = dict(os.environ, MEDICOVER_STORE_PATH=str(Path(args.local).expanduser()))
        cwd = str(Path(__file__).resolve().parent.parent)
    else:
        user = f"mcp_medicover_{args.account}"
        remote = (f"runuser -u {user} -- env MEDICOVER_STORE_PATH=/var/lib/mcp-hub-medicover/{args.account}/credentials.json "
                  f"/opt/medicover-mcp/.venv/bin/medicover-auth set-token --stdin")
        if args.restart:
            remote += f"; rc=$?; systemctl restart mcp-hub-medicover@{args.account}; exit $rc"
        cmd = ["ssh", "-i", str(Path(args.key).expanduser()), args.hub, remote]
        env, cwd = None, None
    done = subprocess.run(cmd, input=token + "\n", text=True, env=env, cwd=cwd)
    return done.returncode


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    where = p.add_mutually_exclusive_group(required=True)
    where.add_argument("--local", metavar="PATH", help="write the credential file at PATH (a local test)")
    where.add_argument("--hub", metavar="USER@HOST", help="deliver to the hub over ssh")
    p.add_argument("--key", default="~/.ssh/homelab_ed25519")
    p.add_argument("--account", default="filip", help="hub account label (with --hub)")
    p.add_argument("--restart", action="store_true", help="restart the account's instance after delivery (with --hub)")
    p.add_argument("--profile", default="~/.medicover-chrome", help="Chrome profile directory kept between runs")
    p.add_argument("--diagnose", action="store_true", help="print what the Chrome profile remembers (cookie names/expiry, storage key names; never values)")
    p.add_argument("--timeout", type=int, default=600, help="seconds to wait for the login")
    args = p.parse_args()

    if not Path(CHROME).exists():
        eprint("Google Chrome not found at", CHROME)
        return 2
    profile = Path(args.profile).expanduser()
    profile.mkdir(parents=True, exist_ok=True)
    chrome = subprocess.Popen(
        [CHROME, f"--remote-debugging-port={PORT}", "--remote-debugging-address=127.0.0.1", f"--user-data-dir={profile}",
         "--no-first-run", "--no-default-browser-check", START_URL],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    eprint("Chrome is open. Log in to Medicover there (password, the emailed code, tick 'trust this device'). Nothing to copy.")
    token = None
    deadline = time.monotonic() + args.timeout
    diagnosed_start = False
    try:
        while time.monotonic() < deadline and token is None:
            time.sleep(1)
            for t in targets():
                if t.get("type") == "page" and HOST in t.get("url", "") and t.get("webSocketDebuggerUrl"):
                    try:
                        if args.diagnose and not diagnosed_start:
                            time.sleep(3)   # let the page load and the SPA decide whether it is signed in
                            diagnose("when Chrome opened", t["webSocketDebuggerUrl"])
                            diagnosed_start = True
                        found = evaluate(t["webSocketDebuggerUrl"], FIND)
                        if found:
                            if args.diagnose:
                                diagnose("at the moment of login", t["webSocketDebuggerUrl"])
                            token = json.loads(found)["t"]
                            evaluate(t["webSocketDebuggerUrl"], WIPE)   # the browser must not refresh a token the server owns
                            break
                    except Exception:
                        continue
    finally:
        close_chrome(chrome)
    if not token:
        eprint("No login seen before the timeout; nothing was saved.")
        return 1
    eprint("Got the session; the browser's copy is removed and Chrome is closed. Delivering...")
    rc = deliver(token, args)
    token = ""   # noqa: F841
    return rc


if __name__ == "__main__":
    sys.exit(main())
