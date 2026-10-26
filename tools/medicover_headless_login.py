# /// script
# requires-python = ">=3.11"
# dependencies = ["websockets>=13"]
# ///
"""EXPERIMENT: log in to Medicover with a username and password in a HEADLESS Chrome from a FRESH profile, the way an unattended job on the hub would.

It answers three questions and nothing else:
  1. does the portal accept a headless browser at the password step (the step it refuses to scripts)?
  2. does it ask for the emailed code on a fresh profile that carries only the trusted device's key ('deviceKey')?
  3. does a session come out (the cookies + refresh token the server needs)?

Run it yourself: the username and password are read from the environment (MEDICOVER_USERNAME / MEDICOVER_PASSWORD) or, if absent, prompted
with the password hidden. They are typed into the portal's own form and never printed, logged or written anywhere by this tool. It prints
only the stages it reached (host and path of the page, never the query) and any visible error text of the portal's form.

    uv run tools/medicover_headless_login.py --local /tmp/creds.json
    uv run tools/medicover_headless_login.py --hub root@192.168.7.119 --key ~/.ssh/homelab_ed25519 --account filip --restart
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import medicover_browser_login as base          # noqa: E402  (CHROME, FIND, session_of, deliver, eprint, targets...)
from websockets.sync.client import connect      # noqa: E402

PORT = 9224
SPA = "https://online24.medicover.pl"
HEADLESS_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"


class Cdp:
    def __init__(self, ws_url: str):
        self.ws = connect(ws_url, max_size=2**23, open_timeout=5)
        self.n = 0

    def call(self, method: str, params: dict | None = None, timeout: float = 15):
        self.n += 1
        self.ws.send(json.dumps({"id": self.n, "method": method, "params": params or {}}))
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            msg = json.loads(self.ws.recv(timeout=max(0.1, end - time.monotonic())))
            if msg.get("id") == self.n:
                return msg.get("result", {})
        raise TimeoutError(method)

    def js(self, expression: str):
        return self.call("Runtime.evaluate", {"expression": expression, "returnByValue": True}).get("result", {}).get("value")

    def close(self):
        try:
            self.ws.close()
        except Exception:
            pass


def launch(profile: Path, port: int, url: str) -> subprocess.Popen:
    return subprocess.Popen(
        [base.CHROME, "--headless=new", f"--remote-debugging-port={port}", "--remote-debugging-address=127.0.0.1", f"--user-data-dir={profile}",
         "--no-first-run", "--no-default-browser-check", "--disable-blink-features=AutomationControlled", f"--user-agent={HEADLESS_UA}", url],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)


def page_ws(port: int, deadline: float) -> str:
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/json", timeout=2) as r:
                pages = [t for t in json.load(r) if t.get("type") == "page" and t.get("webSocketDebuggerUrl")]
            if pages:
                return pages[0]["webSocketDebuggerUrl"]
        except Exception:
            pass
        time.sleep(0.5)
    raise TimeoutError("no page target")


def trusted_device_key(profile: Path) -> str | None:
    """The SPA's 'deviceKey' (what the portal's 'trust this device' is most likely keyed by), read from the persistent profile."""
    chrome = launch(profile, PORT, f"{SPA}/favicon.ico")
    try:
        c = Cdp(page_ws(PORT, time.monotonic() + 20))
        c.call("Page.enable")
        c.call("Page.navigate", {"url": f"{SPA}/favicon.ico"})
        key, end = None, time.monotonic() + 20
        while time.monotonic() < end and not key:
            time.sleep(1)
            if c.js("location.origin") == SPA:
                key = c.js("localStorage.getItem('deviceKey')")
        c.close()
        return key
    finally:
        base.close_chrome_port(chrome, PORT)


STAGE_JS = """(() => { const q = (s) => document.querySelector(s);
  return JSON.stringify({host: location.host, path: location.pathname,
    login: !!q('input[name="Input.Password"]'), mfa: !!q('input[name="Input.MfaCode"]'),
    errors: (document.body.innerText || '').split('\\n').map(x => x.trim()).filter(x => x && x.length < 140 && /incorrect|oops|try again|invalid|error|nieprawid|b\u0142\u0105d|blocked|captcha|too many|locked|zablok/i.test(x)).slice(0,4)}); })()"""


def fill_and_submit(c: Cdp, user: str, password: str) -> None:
    """Type into the portal's own form like a person does: focus the field, insert the text, then press the form's submit button."""
    for name, value in (("Input.Username", user), ("Input.Password", password)):
        c.js(f"(() => {{ const e = document.querySelector('input[name=\"{name}\"]'); e.focus(); e.value = ''; }})()")
        c.call("Input.insertText", {"text": value})
        time.sleep(0.4)
    c.js("(() => { const f = document.querySelector('input[name=\"Input.Password\"]').form; const b = f.querySelector('button[type=submit], input[type=submit], button[name=\"Input.Button\"]'); b ? b.click() : f.requestSubmit(); })()")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    where = p.add_mutually_exclusive_group(required=True)
    where.add_argument("--local", metavar="PATH")
    where.add_argument("--hub", metavar="USER@HOST")
    where.add_argument("--dry", action="store_true", help="log in and report the stages, deliver nothing")
    p.add_argument("--key", default="~/.ssh/homelab_ed25519")
    p.add_argument("--account", default="filip")
    p.add_argument("--restart", action="store_true")
    p.add_argument("--profile", default="~/.medicover-chrome", help="persistent profile to take the trusted device key from")
    p.add_argument("--device-key", help="use this device key instead of reading the profile")
    p.add_argument("--timeout", type=int, default=150)
    args = p.parse_args()

    user = os.environ.get("MEDICOVER_USERNAME") or input("Medicover username (MRN / login): ").strip()
    password = os.environ.get("MEDICOVER_PASSWORD") or getpass.getpass("Medicover password: ")
    if not user or not password:
        base.eprint("username and password are required")
        return 2
    dk = args.device_key or trusted_device_key(Path(args.profile).expanduser())
    base.eprint("trusted device key:", "found" if dk else "NOT found (the portal will treat this as a new device)")

    tmp = Path(tempfile.mkdtemp(prefix="medicover-headless-"))
    chrome = launch(tmp, PORT, "about:blank")
    result = 1
    try:
        c = Cdp(page_ws(PORT, time.monotonic() + 20))
        c.call("Page.enable"); c.call("Network.enable")
        c.call("Network.setUserAgentOverride", {"userAgent": HEADLESS_UA})
        if dk:
            c.call("Page.addScriptToEvaluateOnNewDocument", {"source": f"if (location.origin === {json.dumps(SPA)} && !localStorage.getItem('deviceKey')) localStorage.setItem('deviceKey', {json.dumps(dk)});"})
        c.call("Page.navigate", {"url": SPA + "/"})
        submitted, last, back, deadline = False, None, 0, time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            time.sleep(1.5)
            try:
                st = json.loads(c.js(STAGE_JS) or "{}")
            except Exception:
                continue
            stage = (st.get("host"), st.get("path"), st.get("login"), st.get("mfa"), tuple(st.get("errors") or ()))
            if stage != last:
                base.eprint(f"[stage] {st.get('host')}{st.get('path')}  login-form={st.get('login')}  code-page={st.get('mfa')}  portal-says={st.get('errors') or '-'}")
                last = stage
            if st.get("mfa"):
                base.eprint("RESULT: the portal asks for the emailed code on this fresh profile (trust did not carry over).")
                result = 3
                break
            if st.get("login") and not submitted:
                fill_and_submit(c, user, password)
                submitted = True
                continue
            if st.get("login") and submitted:
                back += 1
                if back >= 3:
                    base.eprint("RESULT: the login form came back after the submit (wrong credentials, or the portal did not let a headless browser through: read what it says)" + (f" (it says: {st.get('errors')})" if st.get("errors") else " (no message shown)") + ".")
                    result = 4
                    break
            else:
                back = 0
            if "online24.medicover.pl" == st.get("host") and not st.get("login"):
                found = c.js(base.FIND)
                if found:
                    base.eprint("RESULT: signed in without the emailed code; a session exists.")
                    if args.dry:
                        result = 0
                        break
                    sess = json.loads(base.session_of_cdp(c, json.loads(found)["t"]))
                    result = base.deliver(json.dumps(sess), args)
                    break
        else:
            base.eprint("RESULT: timed out before a session or a refusal.")
        c.close()
    finally:
        base.close_chrome_port(chrome, PORT)
        shutil.rmtree(tmp, ignore_errors=True)
        password = ""   # noqa: F841
    return result


if __name__ == "__main__":
    sys.exit(main())
