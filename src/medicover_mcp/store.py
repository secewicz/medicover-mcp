"""Secure, local, permission-restricted credential store.

Holds only the long-lived **refresh token** (rotating) plus the ``device_id`` used at
bootstrap. Never the password, never an access token. Written with ``0600`` permissions in a
``0700`` directory; the path is configurable via ``MEDICOVER_STORE_PATH``.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path


class CredentialError(RuntimeError):
    """Raised when stored credentials are missing or unreadable."""


REAUTH_HINT = "session expired or missing — run `medicover-auth login`"


@dataclass
class StoredCredentials:
    refresh_token: str
    device_id: str
    # MRN of the account holder this refresh token authenticates as (informational).
    holder_mrn: int | None = None
    # Fork change: the portal's sign-in session (cookies idsrv*, cookiesession1 of the login host) and the SPA's device key. With
    # them the server renews its own login when a refresh is rejected (auth.silent_signin): no browser, no password, no code.
    sso_cookies: dict | None = None
    sso_device_id: str | None = None

    def to_dict(self) -> dict:
        d = {
            "refresh_token": self.refresh_token,
            "device_id": self.device_id,
            "holder_mrn": self.holder_mrn,
        }
        if self.sso_cookies:
            d["sso_cookies"] = self.sso_cookies
            d["sso_device_id"] = self.sso_device_id
        return d


class CredentialStore:
    """Read/write the persisted refresh token with restrictive file permissions."""

    def __init__(self, path: Path):
        self.path = path

    def exists(self) -> bool:
        return self.path.exists()

    def load(self) -> StoredCredentials:
        if not self.path.exists():
            raise CredentialError(f"no credential store at {self.path} — {REAUTH_HINT}")
        try:
            data = json.loads(self.path.read_text())
            return StoredCredentials(
                refresh_token=data["refresh_token"],
                device_id=data["device_id"],
                holder_mrn=data.get("holder_mrn"),
                sso_cookies=data.get("sso_cookies"),
                sso_device_id=data.get("sso_device_id"),
            )
        except (KeyError, ValueError) as exc:
            raise CredentialError(
                f"credential store at {self.path} is corrupt ({exc}) — {REAUTH_HINT}"
            ) from exc

    def save(self, creds: StoredCredentials) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Tighten the directory too (best-effort; ignored on platforms without POSIX perms).
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        # Write atomically with 0600 from the start so the secret is never world-readable.
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(creds.to_dict(), fh, indent=2)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def update_refresh_token(self, refresh_token: str) -> None:
        """Persist a rotated refresh token, preserving the rest of the record."""
        creds = self.load()
        creds.refresh_token = refresh_token
        self.save(creds)
