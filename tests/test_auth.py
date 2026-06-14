"""Auth primitives: PKCE, JWT, token-set expiry, grant request builders, login scraping."""

from __future__ import annotations

import base64
import hashlib
import time

import httpx
import pytest

from medicover_mcp import auth, config
from medicover_mcp.auth import AuthError, LoginFlow, TokenSet


def test_pkce_challenge_is_s256_of_verifier():
    verifier, challenge = auth.generate_pkce()
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    assert challenge == expected
    assert 43 <= len(verifier) <= 128


def test_jwt_expiry_reads_exp():
    from tests.conftest import make_jwt

    tok = make_jwt(sub=1, exp_in=180)
    exp = auth.jwt_expiry(tok)
    assert exp is not None and abs(exp - (time.time() + 180)) < 5


def test_jwt_expiry_handles_garbage():
    assert auth.jwt_expiry("not-a-jwt") is None


def test_tokenset_expiry_uses_jwt_exp():
    from tests.conftest import make_jwt

    fresh = TokenSet(access_token=make_jwt(1, 180), refresh_token="r", expires_in=180, scope="")
    assert not fresh.is_expired()
    stale = TokenSet(access_token=make_jwt(1, -10), refresh_token="r", expires_in=-10, scope="")
    assert stale.is_expired()


def test_build_refresh_request():
    req = auth.build_refresh_request("RT-1")
    assert req == {
        "grant_type": "refresh_token",
        "refresh_token": "RT-1",
        "scope": config.SCOPE,
        "client_id": "web",
    }


def test_build_token_exchange_request():
    req = auth.build_token_exchange_request(
        refresh_token="RT-h", subject_token="AT-h", target_sub=3914784
    )
    assert req["grant_type"] == config.TOKEN_EXCHANGE_GRANT
    assert req["target_sub"] == "3914784"
    assert req["subject_token"] == "AT-h"
    assert req["subject_token_type"] == config.ACCESS_TOKEN_TYPE
    assert req["scope"] == "offline_access"


def test_build_authorization_code_request_includes_verifier():
    req = auth.build_authorization_code_request("CODE", "VERIFIER")
    assert req["grant_type"] == "authorization_code"
    assert req["code"] == "CODE"
    assert req["code_verifier"] == "VERIFIER"
    assert req["redirect_uri"] == config.REDIRECT_URI


def test_parse_token_response_rejects_invalid_grant():
    resp = httpx.Response(400, json={"error": "invalid_grant"})
    with pytest.raises(AuthError, match="session expired"):
        auth.parse_token_response(resp)


# --- LoginFlow scraping + step machine (mocked transport) -------------------------------

LOGIN_HTML = """
<form id="loginForm" action="/Account/Login?ReturnUrl=%2Fconnect%2Fauthorize%2Fcallback%3Fx%3D1" method="post">
  <input name="Input.ReturnUrl" type="hidden" value="/connect/authorize/callback?x=1"/>
  <input name="Input.Username" type="text" value=""/>
  <input name="Input.Password" type="password" value=""/>
  <input name="__RequestVerificationToken" type="hidden" value="VTOKEN-login"/>
  <input name="Input.IsSimpleAccessRegulationAccepted" type="hidden" value="false"/>
</form>
"""

MFA_HTML = """
<form id="mfaForm" action="/Account/Mfa?ReturnUrl=%2Fconnect%2Fauthorize%2Fcallback%3Fx%3D1" method="post">
  <input name="Input.MfaCodeId" type="hidden" value="mfa-code-id"/>
  <input name="Input.ReturnUrl" type="hidden" value="/connect/authorize/callback?x=1"/>
  <input name="Input.Channel" type="hidden" value="SMS"/>
  <input name="Input.Operation" type="hidden" value="SIGN_IN"/>
  <input name="__RequestVerificationToken" type="hidden" value="VTOKEN-mfa"/>
</form>
"""


def _login_handler(state: dict):
    """Simulate authorize -> login page -> POST login -> Mfa page -> POST mfa -> callback -> token."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/connect/authorize":
            return httpx.Response(302, headers={"location": "/Account/Login?ReturnUrl=x"})
        if path == "/Account/Login" and request.method == "GET":
            return httpx.Response(200, text=LOGIN_HTML)
        if path == "/Account/Login" and request.method == "POST":
            body = request.content.decode()
            assert "Input.Username=2220055" in body
            assert "__RequestVerificationToken=VTOKEN-login" in body
            assert "Input.LoginType=FullLogin" in body
            if state.get("trusted"):
                return httpx.Response(302, headers={"location": "/connect/authorize/callback?x=1"})
            return httpx.Response(302, headers={"location": "/Account/Mfa?ReturnUrl=x"})
        if path == "/Account/Mfa" and request.method == "GET":
            return httpx.Response(200, text=MFA_HTML)
        if path == "/Account/Mfa" and request.method == "POST":
            body = request.content.decode()
            assert "Input.MfaCode=123456" in body
            assert "Input.IsTrustedDevice=true" in body
            return httpx.Response(302, headers={"location": "/connect/authorize/callback?x=1"})
        if path == "/connect/authorize/callback":
            return httpx.Response(
                302, headers={"location": "https://online24.medicover.pl/signin-oidc?code=AUTHCODE&state=s"}
            )
        if path == "/connect/token":
            assert "code=AUTHCODE" in request.content.decode()
            from tests.conftest import token_response

            return httpx.Response(200, json=token_response(2220055, "RT-new"))
        return httpx.Response(404)

    return handler


def _flow_with(handler) -> LoginFlow:
    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    return LoginFlow(client=client)


def test_login_flow_full_mfa_path():
    flow = _flow_with(_login_handler({"trusted": False}))
    flow.begin()
    needs_mfa = flow.submit_password("2220055", "pw")
    assert needs_mfa is True
    flow.request_mfa()
    flow.submit_mfa("123456")
    result = flow.finish()
    assert result.tokens.refresh_token == "RT-new"
    assert result.device_id


def test_login_flow_trusted_device_skips_mfa():
    flow = _flow_with(_login_handler({"trusted": True}))
    flow.begin()
    needs_mfa = flow.submit_password("2220055", "pw")
    assert needs_mfa is False
    result = flow.finish()
    assert result.tokens.refresh_token == "RT-new"


def test_login_flow_rejects_bad_sms_code():
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/connect/authorize":
            return httpx.Response(302, headers={"location": "/Account/Login?ReturnUrl=x"})
        if path == "/Account/Login" and request.method == "GET":
            return httpx.Response(200, text=LOGIN_HTML)
        if path == "/Account/Login":
            return httpx.Response(302, headers={"location": "/Account/Mfa?ReturnUrl=x"})
        if path == "/Account/Mfa" and request.method == "GET":
            return httpx.Response(200, text=MFA_HTML)
        if path == "/Account/Mfa":
            # Wrong code: portal re-renders the MFA page (redirects back to itself).
            return httpx.Response(302, headers={"location": "/Account/Mfa?ReturnUrl=x"})
        return httpx.Response(404)

    flow = _flow_with(handler)
    flow.begin()
    flow.submit_password("2220055", "pw")
    flow.request_mfa()
    with pytest.raises(AuthError, match="not accepted"):
        flow.submit_mfa("123456")
