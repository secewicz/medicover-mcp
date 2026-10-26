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


def test_the_emailed_code_blocks_the_same_way():
    state = {}
    renew.apply_result(state, "code", 10.0, H)
    assert renew.decide(state, 20.0, H) == ("blocked", "code")
    assert renew.decide(state, 20.0, "hash-b")[0] == "go"


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
