"""Okta Users API collector.

Auth is a static SSWS API token (`Authorization: SSWS <token>`). Pagination
is GitHub-style: a `Link: <next-url>; rel="next"` header.

Okta exposes a richer status vocabulary than Google Workspace (STAGED,
PROVISIONED, ACTIVE, RECOVERY, LOCKED_OUT, PASSWORD_EXPIRED, SUSPENDED,
DEPROVISIONED). We collapse the non-active-but-not-deprovisioned states
into a `staged` bucket and the in-good-standing-but-impaired states into
`active`; only SUSPENDED and DEPROVISIONED map to terminal deprovisioned
labels that OFFBOARDED-OWNER cares about.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterator

import httpx

from afterlife import db
from afterlife.collectors.base import Collector
from afterlife.models import Identity

OKTA_STATUS_MAP = {
    "ACTIVE": "active",
    "RECOVERY": "active",
    "PASSWORD_EXPIRED": "active",
    "LOCKED_OUT": "active",
    "STAGED": "staged",
    "PROVISIONED": "staged",
    "SUSPENDED": "suspended",
    "DEPROVISIONED": "deprovisioned",
}


class OktaCollector(Collector):
    source = "okta"

    def __init__(
        self,
        db_path: Path,
        *,
        domain: str | None = None,
        api_token: str | None = None,
        api_url: str | None = None,
    ):
        super().__init__(db_path)
        if not api_token:
            raise ValueError("OktaCollector requires an api_token")
        self.api_token = api_token
        if api_url:
            self.api_url = api_url.rstrip("/")
        elif domain:
            self.api_url = f"https://{domain.rstrip('/')}"
        else:
            raise ValueError("OktaCollector requires domain or api_url")

    def run(self) -> int:
        with httpx.Client(
            base_url=self.api_url,
            headers={
                "Authorization": f"SSWS {self.api_token}",
                "Accept": "application/json",
                "User-Agent": "afterlife/0.1.0",
            },
            timeout=30.0,
        ) as client:
            return self._collect(client)

    def _collect(self, client: httpx.Client) -> int:
        count = 0
        with db.connect(self.db_path) as conn:
            for user in self._iter_users(client):
                db.upsert_identity(conn, self._user_to_identity(user))
                count += 1
        return count

    def _iter_users(self, client: httpx.Client) -> Iterator[dict[str, Any]]:
        url: str | None = "/api/v1/users"
        params: dict[str, Any] | None = {"limit": 200}
        while url:
            r = client.get(url, params=params)
            r.raise_for_status()
            yield from r.json()
            url = _parse_link_next(r.headers.get("Link", ""))
            params = None

    def _user_to_identity(self, user: dict[str, Any]) -> Identity:
        profile = user.get("profile") or {}
        okta_status = (user.get("status") or "").upper()
        first = profile.get("firstName")
        last = profile.get("lastName")
        full_name = " ".join(p for p in (first, last) if p) or None
        return Identity(
            source="okta",
            source_id=user["id"],
            email=profile.get("email"),
            name=full_name,
            status=OKTA_STATUS_MAP.get(okta_status, "unknown"),
            last_seen=None,
            metadata={
                "okta_status": user.get("status"),
                "login": profile.get("login"),
                "created": user.get("created"),
                "activated": user.get("activated"),
                "last_login": user.get("lastLogin"),
            },
        )


def _parse_link_next(link_header: str) -> str | None:
    if not link_header:
        return None
    for part in link_header.split(","):
        part = part.strip()
        if 'rel="next"' in part:
            return part.split(";")[0].strip().strip("<>")
    return None
