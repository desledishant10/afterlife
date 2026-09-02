"""OIDC single sign-on: the login flow plus its security invariants.

A full IdP is mocked with respx (discovery, token, JWKS) and id_tokens are
signed with a real RSA key, so the verification path runs for real. Negative
cases cover state CSRF, nonce replay, expiry, authorization, open redirects,
and the unauthenticated-request behavior.
"""

import time

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

from afterlife.web import create_app
from afterlife.web.oidc import (
    OIDCConfig,
    make_session,
    read_signed,
    safe_next,
)

ISSUER = "https://idp.example.com"
KID = "test-key-1"

_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PRIV_PEM = _priv.private_bytes(
    ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()
).decode()
_jwk = RSAAlgorithm.to_jwk(_priv.public_key(), as_dict=True)
_jwk.update({"kid": KID, "use": "sig", "alg": "RS256"})
JWKS = {"keys": [_jwk]}


def _config(**kw) -> OIDCConfig:
    base = dict(
        issuer=ISSUER,
        client_id="afterlife",
        client_secret="s3cret",
        redirect_uri="http://localhost:8000/auth/callback",
        session_secret="unit-test-session-secret",
        allowed_domains=("example.com",),
    )
    base.update(kw)
    return OIDCConfig(**base)


def _id_token(nonce, *, email="user@example.com", email_verified=True,
              exp_delta=3600, aud="afterlife", iss=ISSUER, kid=KID):
    now = int(time.time())
    claims = {
        "iss": iss, "aud": aud, "sub": "abc-123", "email": email,
        "nonce": nonce, "iat": now, "exp": now + exp_delta,
    }
    if email_verified is not None:  # None omits the claim entirely
        claims["email_verified"] = email_verified
    return jwt.encode(claims, _PRIV_PEM, algorithm="RS256", headers={"kid": kid})


def _mock_discovery_and_jwks():
    respx.get(ISSUER + "/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json={
            "issuer": ISSUER,
            "authorization_endpoint": ISSUER + "/authorize",
            "token_endpoint": ISSUER + "/token",
            "jwks_uri": ISSUER + "/jwks",
        })
    )
    respx.get(ISSUER + "/jwks").mock(return_value=httpx.Response(200, json=JWKS))


def _login(client, config):
    """Drive /auth/login and return the decoded flow (state, nonce, verifier)."""
    r = client.get("/auth/login", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"].startswith(ISSUER + "/authorize")
    flow_cookie = client.cookies.get("afterlife_oidc_flow")
    assert flow_cookie
    return read_signed(flow_cookie, config.session_secret)


# ---------------------------------------------------------------------------
# unit
# ---------------------------------------------------------------------------


def test_safe_next_blocks_open_redirects():
    assert safe_next("/findings") == "/findings"
    assert safe_next("//evil.com") == "/"
    assert safe_next("/\\evil.com") == "/"
    assert safe_next("/a\\b") == "/"          # backslash anywhere
    assert safe_next("/\t/evil") == "/"       # control/whitespace char
    assert safe_next("/ /evil") == "/"        # space
    assert safe_next("https://evil.com") == "/"
    assert safe_next("evil") == "/"
    assert safe_next(None) == "/"


def test_session_token_roundtrip():
    tok = make_session("a@b.com", "sekret", 60)
    assert read_signed(tok, "sekret")["sub"] == "a@b.com"
    assert read_signed(tok, "wrong-secret") is None
    assert read_signed("garbage", "sekret") is None


def test_session_token_expiry():
    import hashlib
    key = hashlib.sha256(b"sekret").digest()
    tok = jwt.encode({"sub": "a@b.com", "iat": 0, "exp": 1}, key, algorithm="HS256")
    assert read_signed(tok, "sekret") is None


def test_config_from_env_requires_core_fields():
    assert OIDCConfig.from_env({}) is None
    cfg = OIDCConfig.from_env({
        "AFTERLIFE_OIDC_ISSUER": ISSUER,
        "AFTERLIFE_OIDC_CLIENT_ID": "afterlife",
        "AFTERLIFE_OIDC_CLIENT_SECRET": "s",
        "AFTERLIFE_OIDC_REDIRECT_URI": "http://x/auth/callback",
        "AFTERLIFE_OIDC_ALLOWED_DOMAINS": "example.com, acme.com",
        "AFTERLIFE_SESSION_SECRET": "fixed",
    })
    assert cfg is not None
    assert cfg.allowed_domains == ("example.com", "acme.com")
    assert cfg.session_secret == "fixed"


def test_authorizes_rules():
    assert _config(allowed_domains=("example.com",)).authorizes("x@example.com")
    assert not _config(allowed_domains=("example.com",)).authorizes("x@evil.com")
    assert _config(allowed_domains=(), allowed_emails=("only@x.com",)).authorizes("only@x.com")
    assert not _config(allowed_domains=(), allowed_emails=("only@x.com",)).authorizes("nope@x.com")
    # No allow-list fails CLOSED by default...
    assert not _config(allowed_domains=(), allowed_emails=()).authorizes("anyone@anywhere.com")
    # ...unless the operator explicitly opts in.
    assert _config(
        allowed_domains=(), allowed_emails=(), allow_any_account=True
    ).authorizes("anyone@anywhere.com")


# ---------------------------------------------------------------------------
# flow
# ---------------------------------------------------------------------------


@respx.mock
def test_unauthenticated_html_redirects_to_login(fresh_db):
    client = TestClient(create_app(fresh_db, oidc=_config()))
    r = client.get("/", headers={"accept": "text/html"}, follow_redirects=False)
    assert r.status_code == 302
    assert "/auth/login?next=%2F" in r.headers["location"]


@respx.mock
def test_unauthenticated_api_gets_401(fresh_db):
    client = TestClient(create_app(fresh_db, oidc=_config()))
    r = client.get("/findings", headers={"accept": "application/json"}, follow_redirects=False)
    assert r.status_code == 401


@respx.mock
def test_full_login_succeeds(fresh_db):
    config = _config()
    _mock_discovery_and_jwks()
    client = TestClient(create_app(fresh_db, oidc=config))

    flow = _login(client, config)
    respx.post(ISSUER + "/token").mock(
        return_value=httpx.Response(200, json={"id_token": _id_token(flow["nonce"])})
    )
    r = client.get(f"/auth/callback?code=abc&state={flow['state']}", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"] == "/"
    assert client.cookies.get("afterlife_session")

    # Now authenticated.
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 200
    assert "Overview" in r.text


@respx.mock
def test_callback_rejects_state_mismatch(fresh_db):
    config = _config()
    _mock_discovery_and_jwks()
    client = TestClient(create_app(fresh_db, oidc=config))
    _login(client, config)
    r = client.get("/auth/callback?code=abc&state=forged", follow_redirects=False)
    assert r.status_code == 400


@respx.mock
def test_callback_rejects_wrong_nonce(fresh_db):
    config = _config()
    _mock_discovery_and_jwks()
    client = TestClient(create_app(fresh_db, oidc=config))
    flow = _login(client, config)
    respx.post(ISSUER + "/token").mock(
        return_value=httpx.Response(200, json={"id_token": _id_token("a-different-nonce")})
    )
    r = client.get(f"/auth/callback?code=abc&state={flow['state']}", follow_redirects=False)
    assert r.status_code == 401
    assert not client.cookies.get("afterlife_session")


@respx.mock
def test_callback_rejects_expired_id_token(fresh_db):
    config = _config()
    _mock_discovery_and_jwks()
    client = TestClient(create_app(fresh_db, oidc=config))
    flow = _login(client, config)
    respx.post(ISSUER + "/token").mock(
        return_value=httpx.Response(200, json={"id_token": _id_token(flow["nonce"], exp_delta=-30)})
    )
    r = client.get(f"/auth/callback?code=abc&state={flow['state']}", follow_redirects=False)
    assert r.status_code == 401


@respx.mock
def test_callback_rejects_unauthorized_domain(fresh_db):
    config = _config(allowed_domains=("example.com",))
    _mock_discovery_and_jwks()
    client = TestClient(create_app(fresh_db, oidc=config))
    flow = _login(client, config)
    bad = _id_token(flow["nonce"], email="intruder@evil.com")
    respx.post(ISSUER + "/token").mock(
        return_value=httpx.Response(200, json={"id_token": bad})
    )
    r = client.get(f"/auth/callback?code=abc&state={flow['state']}", follow_redirects=False)
    assert r.status_code == 403
    assert not client.cookies.get("afterlife_session")


@respx.mock
def test_callback_rejects_wrong_audience(fresh_db):
    config = _config()
    _mock_discovery_and_jwks()
    client = TestClient(create_app(fresh_db, oidc=config))
    flow = _login(client, config)
    bad = _id_token(flow["nonce"], aud="some-other-client")
    respx.post(ISSUER + "/token").mock(
        return_value=httpx.Response(200, json={"id_token": bad})
    )
    r = client.get(f"/auth/callback?code=abc&state={flow['state']}", follow_redirects=False)
    assert r.status_code == 401


@respx.mock
def test_callback_rejects_unverified_email_with_allowlist(fresh_db):
    config = _config(allowed_domains=("example.com",))
    _mock_discovery_and_jwks()
    client = TestClient(create_app(fresh_db, oidc=config))
    flow = _login(client, config)
    bad = _id_token(flow["nonce"], email_verified=None)  # claim absent
    respx.post(ISSUER + "/token").mock(
        return_value=httpx.Response(200, json={"id_token": bad})
    )
    r = client.get(f"/auth/callback?code=abc&state={flow['state']}", follow_redirects=False)
    assert r.status_code == 401
    assert not client.cookies.get("afterlife_session")


@respx.mock
def test_callback_rejects_unknown_kid(fresh_db):
    config = _config()
    _mock_discovery_and_jwks()
    client = TestClient(create_app(fresh_db, oidc=config))
    flow = _login(client, config)
    bad = _id_token(flow["nonce"], kid="unknown-kid")
    respx.post(ISSUER + "/token").mock(
        return_value=httpx.Response(200, json={"id_token": bad})
    )
    r = client.get(f"/auth/callback?code=abc&state={flow['state']}", follow_redirects=False)
    assert r.status_code == 401


@respx.mock
def test_secure_cookie_set_behind_https_proxy(fresh_db):
    config = _config()
    _mock_discovery_and_jwks()
    client = TestClient(create_app(fresh_db, oidc=config))
    r = client.get(
        "/auth/login", headers={"x-forwarded-proto": "https"}, follow_redirects=False
    )
    assert "secure" in r.headers.get("set-cookie", "").lower()


@respx.mock
def test_login_strips_open_redirect_next(fresh_db):
    config = _config()
    _mock_discovery_and_jwks()
    client = TestClient(create_app(fresh_db, oidc=config))
    r = client.get("/auth/login?next=//evil.com", follow_redirects=False)
    assert r.status_code == 302
    flow = read_signed(client.cookies.get("afterlife_oidc_flow"), config.session_secret)
    assert flow["next"] == "/"


@respx.mock
def test_logout_clears_session(fresh_db):
    config = _config()
    _mock_discovery_and_jwks()
    client = TestClient(create_app(fresh_db, oidc=config))
    flow = _login(client, config)
    respx.post(ISSUER + "/token").mock(
        return_value=httpx.Response(200, json={"id_token": _id_token(flow["nonce"])})
    )
    client.get(f"/auth/callback?code=abc&state={flow['state']}", follow_redirects=False)
    assert client.cookies.get("afterlife_session")
    r = client.get("/auth/logout", follow_redirects=False)
    assert r.status_code == 302
    # Session cookie is cleared (deleted).
    assert not client.cookies.get("afterlife_session")


@pytest.mark.parametrize("path", ["/static/style.css", "/auth/login"])
@respx.mock
def test_auth_and_static_paths_reachable_unauthenticated(fresh_db, path):
    config = _config()
    _mock_discovery_and_jwks()
    client = TestClient(create_app(fresh_db, oidc=config))
    r = client.get(path, follow_redirects=False)
    # Not a 401/redirect-to-login: these must be reachable before sign-in.
    assert r.status_code != 401
