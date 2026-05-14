"""Microsoft Entra ID (formerly Azure AD) collector via Microsoft Graph.

Auth uses the OAuth 2.0 client_credentials grant (app-only). The token
endpoint is `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`;
the access token is then sent as a bearer to Graph at
`https://graph.microsoft.com/v1.0`.

For tests and the demo, pass `access_token=...` to bypass the OAuth round
trip. respx then only has to mock the Graph API itself.

Pagination uses Graph's `@odata.nextLink` URL in the response body, which
httpx follows as an absolute URL (overriding base_url) without any extra
handling.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterator

import httpx

from afterlife import db
from afterlife.collectors.base import Collector
from afterlife.models import Identity

API_BASE = "https://graph.microsoft.com/v1.0"
USER_SELECT_FIELDS = (
    "id,displayName,userPrincipalName,mail,accountEnabled,"
    "createdDateTime,signInActivity"
)


class AzureEntraIDCollector(Collector):
    source = "azure"

    def __init__(
        self,
        db_path: Path,
        *,
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        access_token: str | None = None,
        api_url: str = API_BASE,
        token_endpoint: str | None = None,
    ):
        super().__init__(db_path)
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = access_token
        self.api_url = api_url.rstrip("/")
        self.token_endpoint = token_endpoint or (
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
            if tenant_id
            else None
        )

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
        if not (self.tenant_id and self.client_id and self.client_secret):
            raise RuntimeError(
                "tenant_id, client_id, and client_secret are required when "
                "access_token is not provided"
            )
        r = httpx.post(
            self.token_endpoint,
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "https://graph.microsoft.com/.default",
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
        url: str | None = f"/users?$select={USER_SELECT_FIELDS}"
        while url:
            r = client.get(url)
            r.raise_for_status()
            data = r.json()
            yield from data.get("value", [])
            # nextLink is an absolute URL; httpx handles it transparently.
            url = data.get("@odata.nextLink")

    def _user_to_identity(self, user: dict[str, Any]) -> Identity:
        enabled = user.get("accountEnabled")
        status = "active" if enabled else "suspended"
        sign_in = user.get("signInActivity") or {}
        last_sign_in = sign_in.get("lastSignInDateTime")
        return Identity(
            source="azure",
            source_id=str(user["id"]),
            email=user.get("mail") or user.get("userPrincipalName"),
            name=user.get("displayName"),
            status=status,
            last_seen=None,
            metadata={
                "user_principal_name": user.get("userPrincipalName"),
                "created_date_time": user.get("createdDateTime"),
                "last_login_time": last_sign_in,  # naming aligned with INACTIVE-ADMIN
                "account_enabled": enabled,
            },
        )
