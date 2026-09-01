"""Security headers middleware for the local dashboard.

The dashboard is read-only and intended for localhost, but we still set
defense-in-depth headers so the same code is safe if someone runs it
behind a tunnel, on a shared host, or proxies it through a corporate
gateway. None of these headers depend on TLS so they apply uniformly.
"""

from __future__ import annotations

import base64
import binascii
import hmac

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

# style-src needs 'unsafe-inline' because we set a couple of inline style
# attributes in templates (severity-tile color anchors). Everything else
# is locked down to same-origin.
CSP = (
    "default-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "script-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "object-src 'none'"
)

SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": (
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
        "magnetometer=(), microphone=(), payment=(), usb=()"
    ),
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        return response


class BasicAuthMiddleware(BaseHTTPMiddleware):
    """Password-gate the dashboard with HTTP Basic auth (any username).

    A Pro feature: only wired in when `afterlife serve --require-auth` supplies
    a password. Compares in constant time and returns a WWW-Authenticate
    challenge so browsers show a native login prompt.
    """

    def __init__(self, app, password: str):
        super().__init__(app)
        self._password = password

    async def dispatch(self, request: Request, call_next) -> Response:
        if self._authorized(request):
            return await call_next(request)
        return PlainTextResponse(
            "Authentication required.",
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="Afterlife"'},
        )

    def _authorized(self, request: Request) -> bool:
        header = request.headers.get("Authorization", "")
        scheme, _, param = header.partition(" ")
        if scheme.lower() != "basic" or not param:
            return False
        try:
            decoded = base64.b64decode(param, validate=True).decode("utf-8")
        except (binascii.Error, ValueError):
            return False
        _, _, supplied = decoded.partition(":")
        return hmac.compare_digest(supplied, self._password)
