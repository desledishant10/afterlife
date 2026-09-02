"""OIDC single sign-on for the dashboard (Pro).

Implements the OpenID Connect Authorization Code flow with PKCE against any
standards-compliant provider (Google, Okta, Entra, Auth0, Keycloak, ...),
using only httpx + pyjwt (no extra dependency). The flow is protected by:

- **state**: CSRF protection on the callback.
- **nonce**: replay protection, checked inside the id_token.
- **PKCE (S256)**: binds the code exchange to this browser.
- **id_token validation**: RS256 signature via the provider's JWKS, plus issuer,
  audience, expiry, and nonce checks; unverified email addresses are rejected.
- **open-redirect protection**: the post-login `next` target must be a local
  path.

The per-request session is a short-lived HS256 JWT in an HttpOnly cookie signed
with a server secret; nothing is stored server-side. The transient login state
(state/nonce/PKCE verifier) travels in a separate short-lived signed cookie, so
the flow is stateless and works across worker processes.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode

import httpx
import jwt
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, RedirectResponse, Response

FLOW_COOKIE = "afterlife_oidc_flow"
SESSION_COOKIE = "afterlife_session"
DEFAULT_SCOPES = ("openid", "email", "profile")
_ID_TOKEN_ALGS = ["RS256", "RS384", "RS512"]
_HTTP_TIMEOUT = 15.0


class OIDCError(Exception):
    pass


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def safe_next(target: str | None) -> str:
    """Return a safe same-origin redirect path, or '/'.

    Rejects absolute URLs and protocol-relative or backslash tricks so the
    post-login redirect can never leave the dashboard's origin.
    """
    if not target or not target.startswith("/"):
        return "/"
    # Reject control/whitespace characters and backslashes, which browsers or
    # proxies can rewrite into a cross-origin redirect, without relying on the
    # framework to sanitize them later.
    if any(ord(c) < 0x21 for c in target) or "\\" in target:
        return "/"
    if target.startswith("//"):
        return "/"
    return target


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass
class OIDCConfig:
    issuer: str
    client_id: str
    client_secret: str
    redirect_uri: str
    session_secret: str
    scopes: tuple[str, ...] = DEFAULT_SCOPES
    allowed_domains: tuple[str, ...] = ()
    allowed_emails: tuple[str, ...] = ()
    allow_any_account: bool = False
    force_secure_cookies: bool = False
    session_ttl: int = 8 * 3600
    flow_ttl: int = 600

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> OIDCConfig | None:
        env = env if env is not None else dict(os.environ)
        issuer = env.get("AFTERLIFE_OIDC_ISSUER")
        client_id = env.get("AFTERLIFE_OIDC_CLIENT_ID")
        client_secret = env.get("AFTERLIFE_OIDC_CLIENT_SECRET")
        redirect_uri = env.get("AFTERLIFE_OIDC_REDIRECT_URI")
        if not (issuer and client_id and client_secret and redirect_uri):
            return None
        secret = env.get("AFTERLIFE_SESSION_SECRET") or _b64url(secrets.token_bytes(32))
        return cls(
            issuer=issuer,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            session_secret=secret,
            scopes=tuple(
                (env.get("AFTERLIFE_OIDC_SCOPES") or "openid email profile").split()
            ),
            allowed_domains=_csv(env.get("AFTERLIFE_OIDC_ALLOWED_DOMAINS")),
            allowed_emails=_csv(env.get("AFTERLIFE_OIDC_ALLOWED_EMAILS")),
            allow_any_account=_flag(env.get("AFTERLIFE_OIDC_ALLOW_ANY_ACCOUNT")),
            force_secure_cookies=_flag(env.get("AFTERLIFE_OIDC_COOKIE_SECURE")),
        )

    def has_allowlist(self) -> bool:
        return bool(self.allowed_domains or self.allowed_emails)

    def authorizes(self, email: str) -> bool:
        email = email.lower()
        if self.allowed_emails and email in {e.lower() for e in self.allowed_emails}:
            return True
        domain = email.rpartition("@")[2]
        if self.allowed_domains and domain in {d.lower() for d in self.allowed_domains}:
            return True
        # Fail closed: with no allow-list, admit accounts only when the operator
        # explicitly opted in (AFTERLIFE_OIDC_ALLOW_ANY_ACCOUNT).
        if not self.has_allowlist():
            return self.allow_any_account
        return False


def _csv(value: str | None) -> tuple[str, ...]:
    return tuple(p.strip().lower() for p in (value or "").split(",") if p.strip())


def _flag(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


# ---------------------------------------------------------------------------
# Session + flow tokens (HS256, signed with the server secret)
# ---------------------------------------------------------------------------


def _signing_key(secret: str) -> bytes:
    """Derive a 32-byte HMAC key from the configured secret.

    HS256 wants at least a 32-byte key; hashing guarantees the length. It does
    NOT add entropy: a weak AFTERLIFE_SESSION_SECRET is still weak (offline
    brute-forceable into session forgery), so a high-entropy secret must be
    supplied, or one is generated.
    """
    return hashlib.sha256(secret.encode("utf-8")).digest()


def sign_cookie(payload: dict, secret: str) -> str:
    return jwt.encode(payload, _signing_key(secret), algorithm="HS256")


def make_session(email: str, secret: str, ttl: int) -> str:
    now = int(time.time())
    return sign_cookie(
        {"typ": "session", "sub": email, "iat": now, "exp": now + ttl}, secret
    )


def read_signed(
    token: str | None, secret: str, *, expected_typ: str | None = None
) -> dict | None:
    if not token:
        return None
    try:
        claims = jwt.decode(token, _signing_key(secret), algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    # A session cookie and a flow cookie share one key; the `typ` claim stops
    # one from ever validating in the other's role.
    if expected_typ is not None and claims.get("typ") != expected_typ:
        return None
    return claims


# ---------------------------------------------------------------------------
# Provider (discovery + token exchange + id_token verification)
# ---------------------------------------------------------------------------


@dataclass
class _Discovery:
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    issuer: str


class OIDCProvider:
    def __init__(self, config: OIDCConfig):
        self.config = config
        self._discovery: _Discovery | None = None
        self._jwks: dict | None = None

    def discover(self) -> _Discovery:
        if self._discovery is None:
            url = self.config.issuer.rstrip("/") + "/.well-known/openid-configuration"
            resp = httpx.get(url, timeout=_HTTP_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            self._discovery = _Discovery(
                authorization_endpoint=data["authorization_endpoint"],
                token_endpoint=data["token_endpoint"],
                jwks_uri=data["jwks_uri"],
                issuer=data.get("issuer", self.config.issuer),
            )
        return self._discovery

    def authorization_url(self, state: str, nonce: str, code_challenge: str) -> str:
        params = {
            "response_type": "code",
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "scope": " ".join(self.config.scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        return self.discover().authorization_endpoint + "?" + urlencode(params)

    def exchange_code(self, code: str, code_verifier: str) -> dict:
        resp = httpx.post(
            self.discover().token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.config.redirect_uri,
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
                "code_verifier": code_verifier,
            },
            headers={"Accept": "application/json"},
            timeout=_HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()

    def _jwks_dict(self) -> dict:
        if self._jwks is None:
            resp = httpx.get(self.discover().jwks_uri, timeout=_HTTP_TIMEOUT)
            resp.raise_for_status()
            self._jwks = resp.json()
        return self._jwks

    def _signing_key_for(self, kid: str) -> Any:
        for key in jwt.PyJWKSet.from_dict(self._jwks_dict()).keys:
            if key.key_id == kid:
                return key.key
        return None

    def verify_id_token(self, id_token: str, nonce: str) -> dict:
        kid = jwt.get_unverified_header(id_token).get("kid")
        if not kid:
            raise OIDCError("id_token has no kid")
        signing_key = self._signing_key_for(kid)
        if signing_key is None:
            # The key may have rotated; refresh the JWKS once and retry.
            self._jwks = None
            signing_key = self._signing_key_for(kid)
        if signing_key is None:
            raise OIDCError("no matching signing key")
        claims = jwt.decode(
            id_token,
            signing_key,
            algorithms=_ID_TOKEN_ALGS,
            audience=self.config.client_id,
            issuer=self.discover().issuer,
            options={"require": ["exp", "iat", "aud"]},
        )
        if not nonce or claims.get("nonce") != nonce:
            raise OIDCError("nonce mismatch")
        if not claims.get("email"):
            raise OIDCError("no email in id_token")
        # When email is the access-control decision, require proof of ownership:
        # a missing or non-true email_verified is treated as unverified.
        if self.config.has_allowlist() and claims.get("email_verified") is not True:
            raise OIDCError("email not verified")
        return claims


# ---------------------------------------------------------------------------
# Middleware + routes
# ---------------------------------------------------------------------------


class OIDCSessionMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, config: OIDCConfig):
        super().__init__(app)
        self.config = config

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        # Defense in depth: a traversal-looking path is never treated as
        # allow-listed, so the guard does not depend on router normalization.
        odd = ".." in path or "\\" in path or "//" in path
        if not odd and (path.startswith("/auth/") or path.startswith("/static/")):
            return await call_next(request)
        claims = read_signed(
            request.cookies.get(SESSION_COOKIE),
            self.config.session_secret,
            expected_typ="session",
        )
        if claims and claims.get("sub"):
            request.state.user = claims["sub"]
            return await call_next(request)
        accept = request.headers.get("accept", "")
        if request.method == "GET" and "text/html" in accept:
            return RedirectResponse(
                "/auth/login?next=" + quote(path, safe=""), status_code=302
            )
        return PlainTextResponse("Authentication required.", status_code=401)


def install_oidc(app, config: OIDCConfig, *, provider: OIDCProvider | None = None) -> None:
    """Wire OIDC auth into a FastAPI app: session middleware + /auth routes."""
    provider = provider or OIDCProvider(config)
    app.add_middleware(OIDCSessionMiddleware, config=config)

    def _secure(request: Request) -> bool:
        # Set Secure when the request is HTTPS, when a trusted proxy reports
        # HTTPS via X-Forwarded-Proto, or when explicitly forced. (Setting it
        # more often is always safe; it can only refuse to send over plain http.)
        if config.force_secure_cookies or request.url.scheme == "https":
            return True
        return request.headers.get("x-forwarded-proto", "").lower() == "https"

    def _fail(message: str, status_code: int) -> Response:
        # Clear the flow cookie on every terminal path so a login attempt is
        # strictly one-shot (no post-failure reuse of state/nonce/verifier).
        response = PlainTextResponse(message, status_code=status_code)
        response.delete_cookie(FLOW_COOKIE, path="/auth")
        return response

    @app.get("/auth/login")
    def login(request: Request):
        nxt = safe_next(request.query_params.get("next"))
        state = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(24)
        verifier = _b64url(secrets.token_bytes(32))
        challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
        flow = sign_cookie(
            {
                "typ": "flow", "state": state, "nonce": nonce, "verifier": verifier,
                "next": nxt, "exp": int(time.time()) + config.flow_ttl,
            },
            config.session_secret,
        )
        response = RedirectResponse(
            provider.authorization_url(state, nonce, challenge), status_code=302
        )
        response.set_cookie(
            FLOW_COOKIE, flow, max_age=config.flow_ttl, httponly=True,
            samesite="lax", secure=_secure(request), path="/auth",
        )
        return response

    @app.get("/auth/callback")
    def callback(request: Request):
        if request.query_params.get("error"):
            return _fail(
                "Sign-in was cancelled or failed at the identity provider.", 400
            )
        code = request.query_params.get("code")
        state = request.query_params.get("state")
        flow = read_signed(
            request.cookies.get(FLOW_COOKIE), config.session_secret, expected_typ="flow"
        )
        if not (code and state and flow):
            return _fail("Invalid or expired sign-in state.", 400)
        if not secrets.compare_digest(state, str(flow.get("state", ""))):
            return _fail("Sign-in state mismatch.", 400)
        try:
            tokens = provider.exchange_code(code, str(flow["verifier"]))
            id_token = tokens.get("id_token", "")
            claims = provider.verify_id_token(id_token, str(flow.get("nonce", "")))
        except (OIDCError, jwt.PyJWTError, httpx.HTTPError, KeyError):
            return _fail("Sign-in verification failed.", 401)
        email = str(claims.get("email", "")).lower()
        if not config.authorizes(email):
            return _fail("This account is not authorized for this dashboard.", 403)
        response = RedirectResponse(safe_next(flow.get("next")), status_code=302)
        response.set_cookie(
            SESSION_COOKIE, make_session(email, config.session_secret, config.session_ttl),
            max_age=config.session_ttl, httponly=True, samesite="lax",
            secure=_secure(request), path="/",
        )
        response.delete_cookie(FLOW_COOKIE, path="/auth")
        return response

    @app.get("/auth/logout")
    def logout(request: Request):
        response = RedirectResponse("/auth/login", status_code=302)
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response
