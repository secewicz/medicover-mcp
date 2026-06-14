"""Credential store: persistence, rotation, restrictive permissions, clear errors."""

from __future__ import annotations

import stat

import pytest

from medicover_mcp.store import CredentialError, CredentialStore, StoredCredentials


def test_save_and_load_roundtrip(tmp_path):
    s = CredentialStore(tmp_path / "c.json")
    s.save(StoredCredentials(refresh_token="RT", device_id="dev", holder_mrn=2220055))
    loaded = s.load()
    assert loaded.refresh_token == "RT"
    assert loaded.device_id == "dev"
    assert loaded.holder_mrn == 2220055


def test_saved_file_is_not_world_readable(tmp_path):
    s = CredentialStore(tmp_path / "c.json")
    s.save(StoredCredentials(refresh_token="RT", device_id="dev"))
    mode = stat.S_IMODE((tmp_path / "c.json").stat().st_mode)
    assert mode & 0o077 == 0  # no group/other access
    assert mode & 0o600 == 0o600


def test_update_refresh_token_preserves_other_fields(tmp_path):
    s = CredentialStore(tmp_path / "c.json")
    s.save(StoredCredentials(refresh_token="RT0", device_id="dev", holder_mrn=42))
    s.update_refresh_token("RT1")
    loaded = s.load()
    assert loaded.refresh_token == "RT1"
    assert loaded.device_id == "dev"
    assert loaded.holder_mrn == 42


def test_missing_store_raises_actionable_error(tmp_path):
    s = CredentialStore(tmp_path / "missing.json")
    with pytest.raises(CredentialError, match="medicover-auth login"):
        s.load()


def test_corrupt_store_raises_actionable_error(tmp_path):
    p = tmp_path / "c.json"
    p.write_text("{ not json")
    s = CredentialStore(p)
    with pytest.raises(CredentialError, match="medicover-auth login"):
        s.load()
