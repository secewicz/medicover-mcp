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


def extra_chrome_args() -> list[str]:
    """MEDICOVER_CHROME_ARGS (space separated). On Linux, where the hub runs this inside an unprivileged container, the defaults are the
    flags such a container needs: no user-namespace sandbox, no /dev/shm, no GPU. The browser only ever visits Medicover's own pages."""
    env = os.environ.get("MEDICOVER_CHROME_ARGS")
    if env is not None:
        return env.split()
    return ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"] if sys.platform.startswith("linux") else []


def launch(profile: Path, port: int, url: str) -> subprocess.Popen:
    return subprocess.Popen(
        [base.CHROME, "--headless=new", *extra_chrome_args(), f"--remote-debugging-port={port}", "--remote-debugging-address=127.0.0.1", f"--user-data-dir={profile}",
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


def fill_code_and_submit(c: Cdp, code: str, say=base.eprint) -> None:
    """The emailed-code page: type the code, TICK 'trust this device' (so the next login from this device key needs only the password) and press
    CONFIRM. The page may also have a 'send the code again' button, and pressing that instead invalidates the code just typed (seen 26 Oct
    2026), so the button is picked by its value/label, never by being the first one."""
    c.js("(() => { const e = document.querySelector('input[name=\"Input.MfaCode\"]'); e.focus(); e.value = ''; })()")
    c.call("Input.insertText", {"text": code})
    time.sleep(0.4)
    seen = c.js(r"""(() => {
      const f = document.querySelector('input[name="Input.MfaCode"]').form;
      // The 'trust this device' box: the portal's own checkbox may be custom-styled (hidden input + label), so find it by name, then by the words
      // on its label, then as the only checkbox of the form; click it, and force the state if the click did not take.
      const boxes = Array.from(f.querySelectorAll('input[type=checkbox]'));
      const text = (b) => ((b.closest('label') || {}).textContent || '') + ' ' + ((b.id && document.querySelector('label[for="' + b.id + '"]') || {}).textContent || '');
      let box = boxes.find(b => /trust/i.test(b.name)) || boxes.find(b => /trust|zaufa|zapami|remember|urz\u0105dz|device/i.test(text(b)));
      if (!box && boxes.length === 1) box = boxes[0];
      if (box && !box.checked) { box.click(); if (!box.checked) { box.checked = true; box.dispatchEvent(new Event('change', {bubbles: true})); } }
      const trustLabel = box ? text(box).replace(/\s+/g, ' ').trim().slice(0, 50) : null;
      const btns = Array.from(f.querySelectorAll('button, input[type=submit]'));
      const label = (b) => ((b.value || '') + ' ' + (b.textContent || '')).trim();
      const pick = btns.find(b => (b.value || '').toLowerCase() === 'confirm')
        || btns.find(b => /confirm|verify|potwierd|zatwierd|dalej|continue|zaloguj/i.test(label(b)) && !/again|resend|ponown|wy\u015blij/i.test(label(b)))
        || (btns.length === 1 ? btns[0] : null);
      if (pick) pick.click(); else f.requestSubmit();
      return JSON.stringify({trustBox: !!box, trustChecked: box ? box.checked : null, trustLabel: trustLabel, picked: pick ? label(pick).slice(0, 30) : null, buttons: btns.map(b => (b.name || '') + '=' + label(b).slice(0, 24)),
        inputs: Array.from(f.querySelectorAll('input')).map(i => (i.name || '(unnamed)') + ':' + i.type + (i.type === 'checkbox' ? (i.checked ? ':checked' : ':unchecked') : '')),
        labels: Array.from(f.querySelectorAll('label')).map(l => l.textContent.replace(/\s+/g, ' ').trim().slice(0, 40)).filter(Boolean).slice(0, 6)});
    })()""")
    say(f"[code page] submitted: {seen}")


def fill_and_submit(c: Cdp, user: str, password: str) -> None:
    """Type into the portal's own form like a person does: focus the field, insert the text, then press the form's submit button."""
    for name, value in (("Input.Username", user), ("Input.Password", password)):
        c.js(f"(() => {{ const e = document.querySelector('input[name=\"{name}\"]'); e.focus(); e.value = ''; }})()")
        c.call("Input.insertText", {"text": value})
        time.sleep(0.4)
    c.js("(() => { const f = document.querySelector('input[name=\"Input.Password\"]').form; const b = f.querySelector('button[type=submit], input[type=submit], button[name=\"Input.Button\"]'); b ? b.click() : f.requestSubmit(); })()")


def run_login(user: str, password: str, dk: str | None, timeout: int = 150, say=base.eprint,
              code_provider=None, code_wait: int = 480, on_code_page=None, profile: Path | None = None) -> tuple[str, dict | None]:
    """Log in once in a headless Chrome: a fresh throw-away profile, or with `profile` a PERSISTENT one that keeps what the portal remembers
    between runs (the 'trusted device' cookie set when the emailed code is typed with 'trust this device' ticked; a throw-away profile loses it,
    which is why a password-only login kept asking for the code). Returns (status, session): status is 'ok' (session = the JSON the server stores),
    'code' (the portal asks for the emailed code), 'rejected' (the form came back after the submit: wrong password, or refused) or
    'timeout'. With a `code_provider` (a callable returning the six digits once they exist, else None) the emailed-code page is not the end:
    the browser stays open for up to `code_wait` seconds, types the code, ticks 'trust this device' and goes on; `on_code_page()` is called once
    when the page appears. Without one, or when no code arrives in time, the status is 'code'. Nothing secret is printed."""
    if profile is not None:
        tmp = Path(profile)
        tmp.mkdir(mode=0o700, parents=True, exist_ok=True)
        for stale in tmp.glob("Singleton*"):          # a Chrome that was killed leaves these; the next start would refuse the profile
            stale.unlink(missing_ok=True)
    else:
        tmp = Path(tempfile.mkdtemp(prefix="medicover-headless-"))
    chrome = launch(tmp, PORT, "about:blank")
    status, session = "timeout", None
    try:
        c = Cdp(page_ws(PORT, time.monotonic() + 20))
        c.call("Page.enable"); c.call("Network.enable")
        c.call("Network.setUserAgentOverride", {"userAgent": HEADLESS_UA})
        if dk:
            c.call("Page.addScriptToEvaluateOnNewDocument", {"source": f"if (location.origin === {json.dumps(SPA)} && !localStorage.getItem('deviceKey')) localStorage.setItem('deviceKey', {json.dumps(dk)});"})
        c.call("Page.navigate", {"url": SPA + "/"})
        submitted, last, back, deadline = False, None, 0, time.monotonic() + timeout
        announced, code_sent, code_deadline, mfa_after_code = False, False, None, 0
        while time.monotonic() < deadline:
            time.sleep(1.5)
            try:
                st = json.loads(c.js(STAGE_JS) or "{}")
            except Exception:
                continue
            stage = (st.get("host"), st.get("path"), st.get("login"), st.get("mfa"), tuple(st.get("errors") or ()))
            if stage != last:
                say(f"[stage] {st.get('host')}{st.get('path')}  login-form={st.get('login')}  code-page={st.get('mfa')}  portal-says={st.get('errors') or '-'}")
                last = stage
            if st.get("mfa"):
                if code_provider is None:
                    status = "code"
                    break
                if not announced:
                    announced, code_deadline = True, time.monotonic() + code_wait
                    deadline = max(deadline, code_deadline + 60)
                    if on_code_page:
                        on_code_page()
                if code_sent:
                    mfa_after_code += 1
                    if mfa_after_code >= 8:       # still the code page 12 seconds after the code: the portal did not accept it
                        status = "code_rejected"
                        break
                    continue
                code = code_provider()
                if code:
                    fill_code_and_submit(c, code, say)
                    code_sent = True
                    continue
                if time.monotonic() > code_deadline:
                    status = "code"
                    break
                continue
            if st.get("login") and not submitted:
                fill_and_submit(c, user, password)
                submitted = True
                continue
            if st.get("login") and submitted:
                back += 1
                if back >= 3:
                    status = "rejected"
                    break
            else:
                back = 0
            if "online24.medicover.pl" == st.get("host") and not st.get("login"):
                found = c.js(base.FIND)
                if found:
                    status, session = "ok", json.loads(base.session_of_cdp(c, json.loads(found)["t"]))
                    break
        c.close()
    finally:
        base.close_chrome_port(chrome, PORT)             # a graceful close, so the profile's cookies reach the disk
        if profile is None:
            shutil.rmtree(tmp, ignore_errors=True)
    return status, session


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
    p.add_argument("--keep-profile", metavar="DIR", help="keep this headless profile between runs (the way the hub's renewer does) instead of a throw-away one")
    p.add_argument("--ask-code", action="store_true", help="if the portal asks for the emailed code, ask for it here (it is typed with 'trust this device' ticked)")
    p.add_argument("--new-device", action="store_true", help="log in as a BRAND-NEW device (a fresh key, printed so you can reuse it with --device-key)")
    args = p.parse_args()

    user = os.environ.get("MEDICOVER_USERNAME") or input("Medicover username (MRN / login): ").strip()
    password = os.environ.get("MEDICOVER_PASSWORD") or getpass.getpass("Medicover password: ")
    if not user or not password:
        base.eprint("username and password are required")
        return 2
    if args.device_key == "last":
        args.device_key = (Path.home() / ".medicover-test-device-key").read_text().strip()
        base.eprint("using the device key saved by the last --new-device run")
    if args.new_device:
        import uuid
        dk = str(uuid.uuid4())
        (Path.home() / ".medicover-test-device-key").write_text(dk)
        os.chmod(Path.home() / ".medicover-test-device-key", 0o600)
        base.eprint("NEW device key saved for this test: use `--device-key last` next time to check that the password alone is enough")
    else:
        dk = args.device_key or trusted_device_key(Path(args.profile).expanduser())
        base.eprint("trusted device key:", "found" if dk else "NOT found (the portal will treat this as a new device)")

    asked = {"done": False}

    def provider():
        if asked["done"]:
            return None
        asked["done"] = True
        return input("The portal e-mailed you a code. Type it here: ").strip() or None

    status, session = run_login(user, password, dk, args.timeout + (300 if args.ask_code else 0),
                                code_provider=provider if args.ask_code else None,
                                profile=Path(args.keep_profile).expanduser() if args.keep_profile else None)
    password = ""   # noqa: F841
    messages = {"ok": "RESULT: signed in without the emailed code; a session exists.",
                "code": "RESULT: the portal asks for the emailed code on this fresh profile and none was given (trust did not carry over).",
                "code_rejected": "RESULT: a code was typed but the portal stayed on the code page (wrong or expired code, or the wrong button).",
                "rejected": "RESULT: the login form came back after the submit (wrong credentials, or the portal did not let a headless browser through).",
                "timeout": "RESULT: timed out before a session or a refusal."}
    base.eprint(messages[status])
    if status != "ok":
        return {"code": 3, "code_rejected": 3, "rejected": 4}.get(status, 1)
    if args.dry:
        return 0
    return base.deliver(json.dumps(session), args)


if __name__ == "__main__":
    sys.exit(main())
