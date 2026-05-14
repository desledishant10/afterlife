"""Google Workspace (Admin SDK Directory API) collector.

Auth uses a service account with domain-wide delegation, impersonating a
super-admin. The JWT bearer flow is implemented inline against httpx so the
whole network path is mockable with respx, no `google-auth` / `requests`
dependency.

For tests and the demo, pass `access_token=...` directly to skip the OAuth
exchange entirely; respx mocks only the Directory API.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Iterator

import httpx
import jwt

from afterlife import db
from afterlife.collectors.base import Collector
from afterlife.models import Identity

API_BASE = "https://admin.googleapis.com"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
SCOPE = "https://www.googleapis.com/auth/admin.directory.user.readonly"


class GoogleWorkspaceCollector(Collector):
    source = "google"

    def __init__(
        self,
        db_path: Path,
        *,
        service_account_file: str | Path | None = None,
        admin_email: str | None = None,
        access_token: str | None = None,
        api_url: str = API_BASE,
        token_endpoint: str = TOKEN_ENDPOINT,
    ):
        super().__init__(db_path)
        self.service_account_file = service_account_file
        self.admin_email = admin_email
        self.access_token = access_token
        self.api_url = api_url.rstrip("/")
        self.token_endpoint = token_endpoint

    def run(self) -> int:
        token = self.access_token or self._fetch_access_token()
        with httpx.Client(
            base_url=self.api_url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
            timeout=30.0,
        ) as client:
            return self._collect(client)

    def _fetch_access_token(self) -> str:
        if not self.service_account_file or not self.admin_email:
            raise RuntimeError(
                "service_account_file and admin_email are required when "
                "access_token is not provided"
            )
        sa = json.loads(Path(self.service_account_file).read_text())
        now = int(time.time())
        claims = {
            "iss": sa["client_email"],
            "sub": self.admin_email,
            "scope": SCOPE,
            "aud": self.token_endpoint,
            "exp": now + 3600,
            "iat": now,
        }
        signed = jwt.encode(claims, sa["private_key"], algorithm="RS256")
        r = httpx.post(
            self.token_endpoint,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": signed,
            },
            timeout=30.0,
        )
        r.raise_for_status()
        return r.json()["access_token"]

    def _collect(self, client: httpx.Client) -> int:
        count = 0
        with db.connect(self.db_path) as conn:
            for user in self._iter_users(client):
                db.upsert_identity(conn, self._user_to_identity(user))
                count += 1
        return count

    def _iter_users(self, client: httpx.Client) -> Iterator[dict[str, Any]]:
        page_token: str | None = None
        while True:
            params: dict[str, Any] = {"customer": "my_customer", "maxResults": 500}
            if page_token:
                params["pageToken"] = page_token
            r = client.get("/admin/directory/v1/users", params=params)
            r.raise_for_status()
            data = r.json()
            yield from data.get("users", [])
            page_token = data.get("nextPageToken")
            if not page_token:
                return

    def _user_to_identity(self, user: dict[str, Any]) -> Identity:
        if user.get("suspended"):
            status = "suspended"
        elif user.get("archived"):
            status = "archived"
        else:
            status = "active"

        last_login = user.get("lastLoginTime")
        # Google returns this sentinel for users who have never logged in.
        if last_login == "1970-01-01T00:00:00.000Z":
            last_login = None

        return Identity(
            source="google",
            source_id=str(user["id"]),
            email=user.get("primaryEmail") or None,
            name=(user.get("name") or {}).get("fullName"),
            status=status,
            last_seen=None,
            metadata={
                "primary_email": user.get("primaryEmail"),
                "creation_time": user.get("creationTime"),
                "last_login_time": last_login,
                "org_unit_path": user.get("orgUnitPath"),
                "is_admin": user.get("isAdmin"),
                "is_enforced_in_2sv": user.get("isEnforcedIn2Sv"),
                "is_enrolled_in_2sv": user.get("isEnrolledIn2Sv"),
                "suspension_reason": user.get("suspensionReason"),
            },
        )
