"""Shared test helpers. No network: every HTTP call is served by httpx.MockTransport."""

from __future__ import annotations

import base64
import json
import time

import httpx
import pytest

from medicover_mcp import config
from medicover_mcp.client import MedicoverClient
from medicover_mcp.store import CredentialStore, StoredCredentials

HOLDER_MRN = 2220055
CHILD_MRN = 3914784


def make_jwt(sub: int, exp_in: int = 180, scope: str = "openid offline_access profile") -> str:
    """Build an unsigned-but-well-formed JWT carrying sub/exp/scope (signature is a stub)."""
    header = _b64({"alg": "RS256", "typ": "at+jwt"})
    payload = _b64({"sub": str(sub), "exp": int(time.time()) + exp_in, "scope": scope})
    return f"{header}.{payload}.stub-signature"


def _b64(obj: dict) -> str:
    raw = json.dumps(obj).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def token_response(sub: int, refresh: str, exp_in: int = 180) -> dict:
    return {
        "access_token": make_jwt(sub, exp_in),
        "refresh_token": refresh,
        "expires_in": exp_in,
        "token_type": "Bearer",
        "scope": "openid offline_access profile",
    }


@pytest.fixture
def store(tmp_path) -> CredentialStore:
    s = CredentialStore(tmp_path / "creds.json")
    s.save(StoredCredentials(refresh_token="RT-holder-0", device_id="dev-1", holder_mrn=HOLDER_MRN))
    return s


@pytest.fixture
def settings(tmp_path) -> config.Settings:
    return config.Settings(
        store_path=tmp_path / "creds.json", request_timeout=5, username=None, password=None
    )


def build_client(store, settings, handler) -> MedicoverClient:
    """A MedicoverClient whose transport is the given MockTransport handler."""
    c = MedicoverClient(store, settings)
    c._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    c._min_interval = 0  # don't slow the tests
    return c
