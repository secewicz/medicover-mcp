"""OAuth2/OIDC auth for Medicover IdentityServer.

Two concerns live here:

1. **Interactive bootstrap** (`LoginFlow`) — replays the browser's authorization-code + PKCE
   chain including the SMS-2FA step, used only by ``medicover-auth login``. Factored into
   discrete steps (begin → submit_password → request_mfa → submit_mfa → finish) so the flow is
   testable and could back an in-MCP SMS fallback later without restructuring.
2. **Token grants** (pure request builders + parser) — refresh-token rotation and the
   token-exchange used to act on a dependent's behalf. Builders return plain dicts so both the
   sync bootstrap client and the async runtime client can drive them.

Tokens and credentials are never logged here.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field

import httpx

from . import config

_VERIFICATION_TOKEN_RE = re.compile(
    r'name="__RequestVerificationToken"[^>]*\svalue="([^"]+)"'
)
_INPUT_RE = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
_ATTR_RE = re.compile(r'(\w[\w.-]*)="([^"]*)"')
_FORM_ACTION_RE = re.compile(r'<form\b[^>]*\saction="([^"]+)"', re.IGNORECASE)


class AuthError(RuntimeError):
    """Authentication failed (bad credentials, wrong/expired SMS code, expired session…)."""


# --- PKCE -------------------------------------------------------------------------------


def generate_pkce() -> tuple[str, str]:
    """Return ``(code_verifier, code_challenge)`` for PKCE S256."""
    verifier = secrets.token_hex(48)  # 96 chars, within the 43–128 RFC range
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def new_device_id() -> str:
    return str(uuid.uuid4())


# --- JWT helper (decode only; no signature check — we trust the TLS channel) -------------


def jwt_expiry(token: str) -> int | None:
    """Best-effort read of the JWT ``exp`` (unix seconds), or ``None`` if unparseable."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return int(json.loads(base64.urlsafe_b64decode(payload))["exp"])
    except Exception:
        return None


# --- Token set --------------------------------------------------------------------------


@dataclass
class TokenSet:
    access_token: str
    refresh_token: str | None
    expires_in: int
    scope: str
    obtained_at: float = field(default_factory=time.time)

    @classmethod
    def from_response(cls, data: dict) -> "TokenSet":
        if "access_token" not in data:
            raise AuthError(f"token endpoint returned no access_token: {data.get('error', data)}")
        return cls(
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token"),
            expires_in=int(data.get("expires_in", 0)),
            scope=data.get("scope", ""),
        )

    @property
    def expires_at(self) -> float:
        # Prefer the JWT's own exp; fall back to obtained_at + expires_in.
        exp = jwt_expiry(self.access_token)
        return float(exp) if exp is not None else self.obtained_at + self.expires_in

    def is_expired(self, skew: float = config.TOKEN_EXPIRY_SKEW_SECONDS) -> bool:
        return time.time() >= self.expires_at - skew


# --- Token grant request builders (transport-agnostic) ----------------------------------


def build_authorization_code_request(code: str, code_verifier: str) -> dict:
    return {
        "grant_type": "authorization_code",
        "redirect_uri": config.REDIRECT_URI,
        "code": code,
        "code_verifier": code_verifier,
        "client_id": config.CLIENT_ID,
    }


def build_refresh_request(refresh_token: str, scope: str = config.SCOPE) -> dict:
    return {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "scope": scope,
        "client_id": config.CLIENT_ID,
    }


def build_token_exchange_request(
    *, refresh_token: str, subject_token: str, target_sub: int | str
) -> dict:
    """Exchange the holder's token for a dependent-scoped token (see NOTES.md)."""
    return {
        "grant_type": config.TOKEN_EXCHANGE_GRANT,
        "refresh_token": refresh_token,
        "scope": "offline_access",
        "target_sub": str(target_sub),
        "subject_token": subject_token,
        "subject_token_type": config.ACCESS_TOKEN_TYPE,
        "client_id": config.CLIENT_ID,
    }


def parse_token_response(resp: httpx.Response) -> TokenSet:
    if resp.status_code != 200:
        # IdentityServer returns {"error": "..."} on failure; surface it without the body dump.
        err = "unknown_error"
        try:
            err = resp.json().get("error", err)
        except Exception:
            pass
        if err in ("invalid_grant", "invalid_token"):
            raise AuthError("refresh/exchange rejected (invalid_grant) — session expired or revoked")
        raise AuthError(f"token endpoint returned HTTP {resp.status_code} ({err})")
    return TokenSet.from_response(resp.json())


# --- HTML form scraping (login / mfa pages) ---------------------------------------------


def _scrape_verification_token(html: str) -> str:
    m = _VERIFICATION_TOKEN_RE.search(html)
    if not m:
        raise AuthError("could not find the antiforgery token on the login page")
    return m.group(1)


def _scrape_hidden_inputs(html: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for tag in _INPUT_RE.findall(html):
        attrs = dict(_ATTR_RE.findall(tag))
        name = attrs.get("name")
        if name and attrs.get("type", "text").lower() in ("hidden",):
            fields[name] = attrs.get("value", "")
    return fields


def _scrape_form_action(html: str) -> str | None:
    m = _FORM_ACTION_RE.search(html)
    return m.group(1) if m else None


# --- Interactive bootstrap login --------------------------------------------------------


@dataclass
class LoginResult:
    tokens: TokenSet
    device_id: str


class LoginFlow:
    """Drives the interactive browser login (sync httpx) for ``medicover-auth login``.

    Usage::

        flow = LoginFlow()
        flow.begin()
        needs_mfa = flow.submit_password(username, password)
        if needs_mfa:
            flow.request_mfa()            # sends the SMS
            flow.submit_mfa(code)
        result = flow.finish()            # -> LoginResult with the persisted refresh token
    """

    def __init__(self, client: httpx.Client | None = None, device_id: str | None = None):
        self._client = client or httpx.Client(
            timeout=config.Settings.from_env().request_timeout,
            follow_redirects=False,
            headers=dict(config.BROWSER_NAV_HEADERS),
        )
        self._owns_client = client is None
        self.device_id = device_id or new_device_id()
        self._verifier, self._challenge = generate_pkce()
        self._state = secrets.token_hex(16)
        self._login_action: str | None = None
        self._mfa_action: str | None = None
        self._auth_code: str | None = None

    # -- step 1
    def begin(self) -> None:
        """Hit /connect/authorize and load the login page; capture the antiforgery token."""
        params = {
            "client_id": config.CLIENT_ID,
            "redirect_uri": config.REDIRECT_URI,
            "response_type": "code",
            "scope": config.SCOPE,
            "state": self._state,
            "code_challenge": self._challenge,
            "code_challenge_method": "S256",
            "response_mode": "query",
            "ui_locales": "en",
            "app_version": config.APP_VERSION,
            "device_id": self.device_id,
            "device_name": "Chrome",
            "ts": str(int(time.time() * 1000)),
        }
        # Follow the 302 from /authorize to the login page, accumulating cookies.
        resp = self._get_following(config.AUTHORIZE_ENDPOINT, params=params)
        html = resp.text
        self._login_action = self._abs(self._scrape_action_or(resp, html))
        self._login_html = html

    # -- step 2
    def submit_password(self, username: str, password: str) -> bool:
        """POST credentials. Returns True if an SMS-2FA step is required next."""
        if not self._login_action:
            raise AuthError("submit_password called before begin()")
        fields = _scrape_hidden_inputs(self._login_html)
        fields["__RequestVerificationToken"] = _scrape_verification_token(self._login_html)
        fields.update(
            {
                "Input.Username": username,
                "Input.Password": password,
                "Input.LoginType": "FullLogin",
                "Input.Button": "login",
                "Input.IsSimpleAccessRegulationAccepted": "false",
            }
        )
        # Browser submits the login form as a same-origin navigation with Origin: null.
        resp = self._client.post(self._login_action, data=fields, headers={"Origin": "null"})
        location = self._require_redirect(resp, "login")
        if "/Account/Mfa" in location:
            self._mfa_action = self._abs(location)
            return True
        # Trusted device: no MFA. Location is the /connect/authorize/callback.
        self._auth_code = self._follow_to_code(self._abs(location))
        return False

    # -- step 3 (only when MFA required)
    def request_mfa(self) -> None:
        """GET the MFA page — this triggers the SMS — and capture its antiforgery token."""
        if not self._mfa_action:
            raise AuthError("request_mfa called but no MFA step is pending")
        resp = self._get_following(self._mfa_action)
        self._mfa_html = resp.text
        action = self._scrape_form_action_or(resp, self._mfa_html)
        self._mfa_post_action = self._abs(action)

    # -- step 4 (only when MFA required)
    def submit_mfa(self, code: str, trust_device: bool = True) -> None:
        fields = _scrape_hidden_inputs(self._mfa_html)
        fields["__RequestVerificationToken"] = _scrape_verification_token(self._mfa_html)
        fields.update(
            {
                "Input.MfaCode": code.strip(),
                "Input.IsTrustedDevice": "true" if trust_device else "false",
                "Input.DeviceName": "Chrome",
                "Input.Channel": fields.get("Input.Channel", "SMS"),
                "Input.Operation": fields.get("Input.Operation", "SIGN_IN"),
                "Input.Button": "confirm",
            }
        )
        resp = self._client.post(self._mfa_post_action, data=fields, headers={"Origin": "null"})
        location = self._require_redirect(resp, "mfa")
        if "/Account/Mfa" in location:
            raise AuthError("the SMS code was not accepted — check the code and try again")
        self._auth_code = self._follow_to_code(self._abs(location))

    # -- step 5
    def finish(self) -> LoginResult:
        if not self._auth_code:
            raise AuthError("login is not complete — no authorization code obtained")
        resp = self._client.post(
            config.TOKEN_ENDPOINT,
            data=build_authorization_code_request(self._auth_code, self._verifier),
            headers={"Accept": "application/json"},
        )
        tokens = parse_token_response(resp)
        if self._owns_client:
            self._client.close()
        return LoginResult(tokens=tokens, device_id=self.device_id)

    # -- internals
    def _follow_to_code(self, url: str) -> str:
        """Follow /connect/authorize/callback until it redirects to signin-oidc?code=..."""
        seen = 0
        while seen < 10:
            resp = self._client.get(url)
            if resp.status_code not in (301, 302, 303, 307, 308):
                raise AuthError("authorization callback did not return the expected redirect")
            location = resp.headers["location"]
            code = self._extract_code(location)
            if code:
                return code
            url = self._abs(location)
            seen += 1
        raise AuthError("too many redirects while completing authorization")

    @staticmethod
    def _extract_code(location: str) -> str | None:
        parsed = urllib.parse.urlparse(location)
        qs = urllib.parse.parse_qs(parsed.query)
        if "code" in qs:
            return qs["code"][0]
        return None

    def _get_following(self, url: str, params: dict | None = None) -> httpx.Response:
        resp = self._client.get(url, params=params)
        seen = 0
        while resp.status_code in (301, 302, 303, 307, 308) and seen < 10:
            url = self._abs(resp.headers["location"])
            resp = self._client.get(url)
            seen += 1
        return resp

    def _require_redirect(self, resp: httpx.Response, step: str) -> str:
        if resp.status_code not in (301, 302, 303, 307, 308):
            if step == "login":
                raise AuthError("login failed — check username/password")
            raise AuthError(f"{step} step did not redirect (HTTP {resp.status_code})")
        return resp.headers["location"]

    def _scrape_action_or(self, resp: httpx.Response, html: str) -> str:
        return _scrape_form_action(html) or str(resp.url)

    def _scrape_form_action_or(self, resp: httpx.Response, html: str) -> str:
        return _scrape_form_action(html) or str(resp.url)

    def _abs(self, url: str) -> str:
        return urllib.parse.urljoin(config.AUTH_HOST + "/", url)
