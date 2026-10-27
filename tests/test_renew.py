"""The renewer's safety rules (tools/medicover_renew.py): attempt limits, blocks, and what lifts them. No browser, no network."""
from __future__ import annotations

import importlib.util
import json
import stat
from pathlib import Path

spec = importlib.util.spec_from_file_location("medicover_renew", Path(__file__).resolve().parent.parent / "tools" / "medicover_renew.py")
renew = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renew)

H = "hash-a"


def test_a_clean_state_goes():
    assert renew.decide({}, 1000.0, H) == ("go", "")


def test_one_browser_login_per_ten_minutes():
    state = {"attempts": [1000.0]}
    assert renew.decide(state, 1000.0 + 599, H)[0] == "wait"
    assert renew.decide(state, 1000.0 + 601, H)[0] == "go"


def test_six_logins_a_day_then_wait():
    now = 100_000.0
    state = {"attempts": [now - 80_000 + i * 700 for i in range(6)]}
    assert renew.decide(state, now, H)[0] == "wait"
    old = {"attempts": [now - 90_000 + i * 700 for i in range(6)]}     # all older than 24 h: forgotten
    assert renew.decide(old, now, H) == ("go", "")


def test_a_rejected_password_blocks_and_only_a_changed_secret_lifts_it():
    state = {}
    renew.apply_result(state, "rejected", 10.0, H)
    assert renew.decide(state, 99_999.0, H) == ("blocked", "password")
    assert renew.decide(state, 99_999.0, "hash-b")[0] == "go"          # the password in SOPS changed
    assert state["blocked"] is None


def test_the_code_page_blocks_for_good_and_only_a_changed_secret_lifts_it():
    state = {}
    renew.apply_result(state, "code", 10.0, H)
    assert "until" not in state["blocked"]
    assert renew.decide(state, 20.0, H) == ("blocked", "code")
    assert renew.decide(state, 20.0 + 30 * 86400, H) == ("blocked", "code")     # a month later: still nothing, so no hourly e-mails
    state2 = {}
    renew.apply_result(state2, "code", 10.0, H)
    assert renew.decide(state2, 20.0, "hash-b")[0] == "go"


def test_three_plain_failures_block_for_six_hours_only():
    state = {}
    for _ in range(2):
        renew.apply_result(state, "timeout", 100.0, H)
        assert not state.get("blocked")
    renew.apply_result(state, "timeout", 100.0, H)
    assert renew.decide(state, 100.0 + 3600, H) == ("blocked", "repeated")
    assert renew.decide(state, 100.0 + 7 * 3600, H)[0] == "go"


def test_success_clears_failures_and_blocks():
    state = {"failures": 2, "blocked": {"reason": "repeated", "until": 1e12}}
    renew.apply_result(state, "ok", 5.0, H)
    assert state["failures"] == 0 and state["blocked"] is None


def test_the_hash_depends_on_all_three_values_and_hides_them():
    a = renew.secret_hash("u", "p", "k")
    assert a != renew.secret_hash("u", "p2", "k") != renew.secret_hash("u", "p", "k2")
    assert "p" * 3 not in a and len(a) == 16


def test_exit_codes():
    assert renew.BLOCK_EXIT == {"code": 3, "password": 4, "repeated": 5}


def test_state_file_is_private_and_atomic(tmp_path):
    path = tmp_path / "renewal.json"
    renew.save_state(path, {"attempts": [1.0]})
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(path.read_text()) == {"attempts": [1.0]}
    assert renew.load_state(tmp_path / "missing.json") == {}
    (tmp_path / "bad.json").write_text("not json")
    assert renew.load_state(tmp_path / "bad.json") == {}


def test_the_state_never_holds_the_password(tmp_path):
    state = {}
    renew.apply_result(state, "rejected", 1.0, renew.secret_hash("934013", "hunter2-secret", "devkey"))
    blob = json.dumps(state)
    assert "hunter2-secret" not in blob and "devkey" not in blob and "934013" not in blob


def test_env_values_accept_base64_so_any_password_survives_the_env_file(monkeypatch):
    import base64
    monkeypatch.setenv("MEDICOVER_PASSWORD_B64", base64.b64encode('p "a" \\ $x \u0105 '.encode()).decode())
    monkeypatch.setenv("MEDICOVER_PASSWORD", "ignored")
    assert renew.env_value("MEDICOVER_PASSWORD") == 'p "a" \\ $x \u0105 '
    monkeypatch.setenv("MEDICOVER_PASSWORD_B64", "!!not base64!!")
    assert renew.env_value("MEDICOVER_PASSWORD") == ""
    monkeypatch.delenv("MEDICOVER_PASSWORD_B64")
    assert renew.env_value("MEDICOVER_PASSWORD") == "ignored"


def test_take_code_reads_digits_once_and_deletes_the_file(tmp_path):
    f = tmp_path / "pending-code.txt"
    f.write_text(" 123456\n")
    assert renew.take_code(f) == "123456" and not f.exists()
    assert renew.take_code(f) is None
    for bad in ("12", "12ab56", "123456789", "1 2 3"):
        f.write_text(bad)
        assert renew.take_code(f) is None and not f.exists(), bad


def test_the_status_file_is_public_and_holds_no_secret(tmp_path):
    import stat
    path = tmp_path / "run" / "status.json"
    renew.write_status(str(path), "filip", "awaiting_code", deadline=123)
    d = json.loads(path.read_text())
    assert d["state"] == "awaiting_code" and d["deadline"] == 123 and d["account"] == "filip"
    assert stat.S_IMODE(path.stat().st_mode) == 0o644
    renew.write_status(None, "filip", "ok")            # no path: silently nothing


def test_a_code_the_portal_did_not_accept_blocks_like_a_code_that_never_came():
    state = {}
    renew.apply_result(state, "code_rejected", 10.0, H)
    assert state["blocked"]["reason"] == "code" and renew.decide(state, 20.0, H) == ("blocked", "code")


# --- main() with a fake browser: the two modes ---------------------------------------------------------------------------------------

def _run(tmp_path, monkeypatch, *, enrol, alive, login, state=None, capsys=None):
    """Run main() once. `login(kwargs)` plays the browser; it returns (status, session)."""
    import sys
    import types
    calls = []
    fake = types.ModuleType("medicover_headless_login")

    def run_login(user, password, dk, timeout, **kw):
        calls.append(kw)
        return login(kw)
    fake.run_login = run_login
    monkeypatch.setitem(sys.modules, "medicover_headless_login", fake)
    monkeypatch.setattr(renew, "alive", lambda port: _const(alive))
    monkeypatch.setattr(renew, "deliver", lambda *a: True)
    monkeypatch.setenv("MEDICOVER_USERNAME", "u")
    monkeypatch.setenv("MEDICOVER_PASSWORD", "p")
    monkeypatch.setenv("MEDICOVER_STORE_PATH", str(tmp_path / "creds.json"))
    monkeypatch.setenv("MEDICOVER_STATUS_FILE", str(tmp_path / "status.json"))
    sf = tmp_path / "renewal.json"
    if state is not None:
        sf.write_text(json.dumps(state))
    code = renew.main(["--account", "a", "--port", "1", "--state-file", str(sf)] + (["--enrol"] if enrol else []))
    return code, calls, json.loads(sf.read_text()), json.loads((tmp_path / "status.json").read_text())


async def _const(v):
    return v


def test_a_never_enrolled_account_does_not_try_the_password(tmp_path, monkeypatch):
    code, calls, state, status = _run(tmp_path, monkeypatch, enrol=False, alive=False, login=lambda kw: ("ok", {}))
    assert code == renew.EXIT_CODE and calls == [] and status["state"] == "needs_enrolment"


def test_a_scheduled_run_never_waits_for_a_code_and_a_code_page_blocks_it_for_good(tmp_path, monkeypatch):
    code, calls, state, status = _run(tmp_path, monkeypatch, enrol=False, alive=False, state={"enrolled": True}, login=lambda kw: ("code", None))
    assert calls[0]["code_provider"] is None and calls[0]["on_code_page"] is None
    assert code == renew.EXIT_CODE and status["state"] == "blocked_code" and "until" not in state["blocked"]
    again = _run(tmp_path, monkeypatch, enrol=False, alive=False, login=lambda kw: (_ for _ in ()).throw(AssertionError("must not log in")))
    assert again[0] == renew.EXIT_CODE and again[1] == []                      # the next timer run does not touch the portal


def test_enrol_waits_for_the_code_lifts_the_block_and_marks_the_device_enrolled(tmp_path, monkeypatch):
    blocked = {"enrolled": True, "blocked": {"reason": "code", "secret": "x", "at": 1.0}}
    code, calls, state, status = _run(tmp_path, monkeypatch, enrol=True, alive=True, state=blocked, login=lambda kw: ("ok", {"s": 1}))
    assert callable(calls[0]["code_provider"]) and callable(calls[0]["on_code_page"])
    assert code == 0 and state["enrolled"] is True and state["blocked"] is None and status["state"] == "ok"


def test_enrol_is_limited_to_three_a_day(tmp_path, monkeypatch):
    import time
    now = time.time()
    code, calls, state, status = _run(tmp_path, monkeypatch, enrol=True, alive=False, state={"enrol_attempts": [now - 60, now - 120, now - 180]}, login=lambda kw: ("ok", {}))
    assert calls == [] and status["state"] == "waiting"


def test_every_login_uses_the_persistent_profile_next_to_the_state_file(tmp_path, monkeypatch):
    _, calls, _, _ = _run(tmp_path, monkeypatch, enrol=False, alive=False, state={"enrolled": True}, login=lambda kw: ("timeout", None))
    assert calls[0]["profile"] == tmp_path / "chrome"
