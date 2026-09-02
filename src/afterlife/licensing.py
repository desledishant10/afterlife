"""Offline license verification for the open-core Pro edition.

A license is a JWT signed by the vendor's Ed25519 private key. The shipped
application embeds only the *public* key (below), so it can verify a license
entirely offline -- no license server to run or call. The private key never
ships; it is used by the vendor's issuing tool (scripts/issue_license.py) to
mint keys after a purchase.

Everything Afterlife did through Milestone 4 is free. Pro features check
`has_feature(...)` at their call site; without a valid, unexpired Pro license
those paths refuse and point the user at `afterlife license`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt

# Vendor public key. Safe to embed and distribute -- it can only *verify*
# licenses, never mint them. Rotating it means shipping a new release.
VENDOR_PUBLIC_KEY = """\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAyPMIvayk9XoXhwPtobvJStzvU3Vpk7YupTdE60obQNo=
-----END PUBLIC KEY-----
"""

_ALGORITHM = "EdDSA"

# Pro feature registry: id -> human description (shown by `afterlife license`).
FEATURE_DASHBOARD_AUTH = "dashboard_auth"
FEATURE_INTEGRATIONS = "integrations"
PRO_FEATURES: dict[str, str] = {
    FEATURE_DASHBOARD_AUTH: "Password-protect the web dashboard (afterlife serve --require-auth)",
    FEATURE_INTEGRATIONS: "Ticketing integrations: file a Jira issue for new findings",
}


@dataclass
class License:
    customer: str
    edition: str = "free"
    features: list[str] = field(default_factory=list)
    issued_at: datetime | None = None
    expires_at: datetime | None = None

    @property
    def is_pro(self) -> bool:
        return self.edition == "pro"

    def grants(self, feature: str) -> bool:
        """True if this license enables `feature`.

        A Pro license with no explicit feature list grants every Pro feature;
        a license that lists features grants only those.
        """
        if not self.is_pro:
            return False
        return not self.features or feature in self.features


def issue_license(
    private_key_pem: str,
    customer: str,
    *,
    edition: str = "pro",
    features: list[str] | None = None,
    expires_in_days: int | None = 365,
    now: datetime | None = None,
) -> str:
    """Mint a signed license token. Vendor-side (needs the private key)."""
    now = now or datetime.now(UTC)
    claims: dict = {
        "sub": customer,
        "edition": edition,
        "iat": int(now.timestamp()),
    }
    if features:
        claims["features"] = list(features)
    if expires_in_days is not None:
        claims["exp"] = int((now + timedelta(days=expires_in_days)).timestamp())
    return jwt.encode(claims, private_key_pem, algorithm=_ALGORITHM)


def verify_license(
    token: str, public_key_pem: str | None = None
) -> License | None:
    """Verify a token's signature and expiry. Returns None if invalid.

    Reads VENDOR_PUBLIC_KEY at call time (not as a bound default) so it can be
    overridden per call and stays correct if the embedded key is rotated.
    """
    key = public_key_pem or VENDOR_PUBLIC_KEY
    try:
        claims = jwt.decode(token, key, algorithms=[_ALGORITHM])
    except jwt.PyJWTError:
        return None
    return License(
        customer=str(claims.get("sub", "")),
        edition=str(claims.get("edition", "free")),
        features=list(claims.get("features", [])),
        issued_at=_to_dt(claims.get("iat")),
        expires_at=_to_dt(claims.get("exp")),
    )


def _to_dt(value: object) -> datetime | None:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, UTC)
    return None


def load_license_token(env: dict[str, str] | None = None) -> str | None:
    """Read the license token from AFTERLIFE_LICENSE or AFTERLIFE_LICENSE_FILE."""
    env = env if env is not None else dict(os.environ)
    token = env.get("AFTERLIFE_LICENSE")
    if token and token.strip():
        return token.strip()
    path = env.get("AFTERLIFE_LICENSE_FILE")
    if path and Path(path).exists():
        return Path(path).read_text().strip()
    return None


def current_license(env: dict[str, str] | None = None) -> License | None:
    token = load_license_token(env)
    return verify_license(token) if token else None


def edition(env: dict[str, str] | None = None) -> str:
    lic = current_license(env)
    return "pro" if (lic and lic.is_pro) else "free"


def has_feature(feature: str, env: dict[str, str] | None = None) -> bool:
    lic = current_license(env)
    return bool(lic and lic.grants(feature))
