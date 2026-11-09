"""What the headless login (tools/medicover_headless_login.py) calls a login form that comes back after the submit. Only the portal's own
wrong-credentials message is 'rejected' (the renewer blocks the account for good on it); a portal outage is not. No browser, no network:
run_login's real loop is driven by a fake DevTools connection that plays the portal's pages."""
from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent / "tools"


def _load():
    """Load the tool. It imports websockets (a script dependency, not a test one): stub it for the import only."""
    stubs = {}
    if importlib.util.find_spec("websockets") is None:
        client = types.ModuleType("websockets.sync.client")
        client.connect = lambda *a, **k: (_ for _ in ()).throw(AssertionError("no real browser in tests"))
        stubs = {"websockets": types.ModuleType("websockets"), "websockets.sync": types.ModuleType("websockets.sync"),
                 "websockets.sync.client": client}
    saved = {k: sys.modules.get(k) for k in stubs}
    sys.modules.update(stubs)
    try:
        spec = importlib.util.spec_from_file_location("medicover_headless_login_under_test", TOOLS / "medicover_headless_login.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v


hl = _load()

LOGIN = {"host": "login-online24.medicover.pl", "path": "/Account/Login", "login": True, "mfa": False, "errors": []}
WRONG = "Incorrect data. Please try again."           # what the portal showed on 26 Oct 2026 for made-up credentials


def page(**kw):
    return {**LOGIN, **kw}


def response(status: int, url: str) -> dict:
    return {"method": "Network.responseReceived", "params": {"response": {"status": status, "url": url}}}


class FakeCdp(hl.Cdp):
    """The real Cdp's event handling, without a socket: STAGE_JS polls return the scripted pages in turn (the last one repeats), and the
    network events are fed through on_event before the first poll and at the submit, as they would arrive between replies."""

    def __init__(self, pages, before=(), at_submit=()):
        self.server_errors = []
        self.pages, self.before, self.at_submit = list(pages), list(before), list(at_submit)
        self.calls = []

    def call(self, method, params=None, timeout=15):
        self.calls.append((method, params or {}))
        return {}

    def js(self, expression):
        if expression == hl.STAGE_JS:
            for ev in self.before:
                self.on_event(ev)
            self.before = []
            return json.dumps(self.pages.pop(0) if len(self.pages) > 1 else self.pages[0])
        if "requestSubmit" in expression:              # fill_and_submit pressing the form's button
            for ev in self.at_submit:
                self.on_event(ev)
        return None

    def close(self):
        pass


@pytest.fixture
def portal(monkeypatch):
    """run_login against a fake portal: returns a function (pages, before, at_submit, timeout) -> (status, the fake, what it said)."""
    def run(pages, before=(), at_submit=(), timeout=30):
        fake = FakeCdp(pages, before, at_submit)
        said = []
        monkeypatch.setattr(hl, "launch", lambda *a, **k: object())
        monkeypatch.setattr(hl, "page_ws", lambda *a, **k: "ws://fake")
        monkeypatch.setattr(hl, "Cdp", lambda url: fake)
        monkeypatch.setattr(hl.base, "close_chrome_port", lambda *a, **k: None)
        monkeypatch.setattr(hl.time, "sleep", lambda s: None)
        status, session = hl.run_login("u", "p", "device-key", timeout, say=said.append)
        assert session is None
        return status, fake, said
    return run


def test_the_portals_wrong_credentials_message_is_a_rejection(portal):
    status, _, said = portal([LOGIN, page(errors=[WRONG])])
    assert status == "rejected"
    assert any(WRONG in s for s in said)


def test_a_form_back_without_that_message_is_not_a_rejection(portal):
    # 8 Nov 2026: the form came back for all three accounts within two minutes while the portal answered 500; nothing said the password was wrong
    status, _, _ = portal([LOGIN, LOGIN])
    assert status == "form_back"


def test_other_portal_text_is_not_a_rejection(portal):
    status, _, _ = portal([LOGIN, page(errors=["Oops! We’re diagnosing the problem. Come back to us in a moment."])])
    assert status == "form_back"


def test_a_5xx_after_the_submit_is_a_portal_error_even_with_the_message(portal):
    status, fake, said = portal([LOGIN, page(errors=[WRONG])],
                                at_submit=[response(500, "https://login-online24.medicover.pl/Account/Login?ReturnUrl=%2Fconnect%2Fauthorize%3Fsecret")])
    assert status == "portal_error"
    assert fake.server_errors == ["500 login-online24.medicover.pl/Account/Login"]       # status, host and path: never the query
    assert not any("secret" in s or "ReturnUrl" in s for s in said)


def test_a_5xx_before_the_submit_does_not_count(portal):
    status, _, _ = portal([LOGIN, page(errors=[WRONG])], before=[response(502, "https://online24.medicover.pl/api/config")])
    assert status == "rejected"


def test_an_outage_that_never_shows_the_form_again_is_a_portal_error_not_a_timeout(portal):
    error_page = {"host": "login-online24.medicover.pl", "path": "/Home/Error", "login": False, "mfa": False, "errors": []}
    status, _, _ = portal([LOGIN, error_page], at_submit=[response(503, "https://login-online24.medicover.pl/Account/Login")], timeout=0.2)
    assert status == "portal_error"
    status, _, _ = portal([LOGIN, error_page], timeout=0.2)
    assert status == "timeout"


def test_the_browser_asks_for_the_language_the_message_is_matched_in(portal):
    _, fake, _ = portal([LOGIN, page(errors=[WRONG])])
    override = [p for m, p in fake.calls if m == "Network.setUserAgentOverride"]
    assert override and override[0]["acceptLanguage"].startswith("en")


@pytest.mark.parametrize("errors, server_errors, expected", [
    ([WRONG], [], "rejected"),
    (["INCORRECT DATA. please try again."], [], "rejected"),
    (["Something else went wrong"], [], "form_back"),
    ([], [], "form_back"),
    ([WRONG], ["500 login-online24.medicover.pl/connect/token"], "portal_error"),
    ([], ["503 online24.medicover.pl/"], "portal_error"),
])
def test_form_back_status(errors, server_errors, expected):
    assert hl.form_back_status(errors, server_errors) == expected


def test_only_a_medicover_hosts_5xx_is_kept():
    fake = FakeCdp([LOGIN])
    fake.on_event(response(500, "https://www.googletagmanager.com/gtm.js"))       # not the portal
    fake.on_event(response(404, "https://login-online24.medicover.pl/favicon.ico"))  # not a server error
    fake.on_event(response(401, "https://api-gateway-online24.medicover.pl/x"))      # the API before a login: normal
    fake.on_event({"method": "Network.loadingFinished", "params": {}})
    assert fake.server_errors == []
    fake.on_event(response(500, "https://api-gateway-online24.medicover.pl/api/v4/available-profiles/me"))
    assert fake.server_errors == ["500 api-gateway-online24.medicover.pl/api/v4/available-profiles/me"]
