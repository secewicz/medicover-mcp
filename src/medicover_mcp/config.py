"""Static configuration and runtime settings for the Medicover client.

Nothing secret lives here. Credentials come from environment variables (only at bootstrap)
and the persisted refresh token lives in the credential store (see ``store.py``).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# --- Discovered hosts / OIDC constants (see NOTES.md) -----------------------------------

AUTH_HOST = "https://login-online24.medicover.pl"
API_HOST = "https://api-gateway-online24.medicover.pl"
SPA_ORIGIN = "https://online24.medicover.pl"

# Public OAuth client (no secret); PKCE is used.
CLIENT_ID = "web"
REDIRECT_URI = f"{SPA_ORIGIN}/signin-oidc"
SCOPE = "openid offline_access profile"

AUTHORIZE_ENDPOINT = f"{AUTH_HOST}/connect/authorize"
TOKEN_ENDPOINT = f"{AUTH_HOST}/connect/token"
LOGIN_PAGE = f"{AUTH_HOST}/Account/Login"
MFA_PAGE = f"{AUTH_HOST}/Account/Mfa"
PROFILES_ENDPOINT = f"{AUTH_HOST}/api/v4/available-profiles/me"

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"

# A stable, honest User-Agent. The portal's own SPA uses a Chrome UA; we identify as an
# automation client but keep the app_version the SPA advertised so requests look well-formed.
USER_AGENT = "medicover-mcp/0.1 (+https://github.com/; unattended appointment agent)"
APP_VERSION = "3.30.0-beta.1.2"

# Refresh access tokens this many seconds before their real expiry (they only live ~180s).
TOKEN_EXPIRY_SKEW_SECONDS = 30

DEFAULT_STORE_PATH = Path.home() / ".config" / "medicover-mcp" / "credentials.json"


@dataclass(frozen=True)
class Settings:
    """Resolved runtime settings."""

    store_path: Path
    request_timeout: float
    # Only consulted at bootstrap (medicover-auth login); never by the MCP runtime.
    username: str | None
    password: str | None

    @classmethod
    def from_env(cls) -> "Settings":
        store = os.environ.get("MEDICOVER_STORE_PATH")
        return cls(
            store_path=Path(store).expanduser() if store else DEFAULT_STORE_PATH,
            request_timeout=float(os.environ.get("MEDICOVER_TIMEOUT", "30")),
            username=os.environ.get("MEDICOVER_USERNAME"),
            password=os.environ.get("MEDICOVER_PASSWORD"),
        )
