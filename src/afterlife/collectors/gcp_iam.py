"""GCP IAM collector: service accounts and their user-managed keys.

Auth uses the same JWT-bearer flow as the Google Workspace collector but
with the `cloud-platform.read-only` scope. The collector enumerates service
accounts in one project, then enumerates each SA's user-managed keys.
System-managed keys (Google's internally rotated ones) are intentionally
excluded; they are not actionable.

Service accounts are modeled as Identity rows (source=gcp). Their keys are
Credential rows owned by the SA. The GCP IAM API does not expose key
last-used data on the standard endpoint, so `last_used_at` stays None and
NEVER-USED-style rules know to skip this credential type.
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

import httpx
import jwt

from afterlife import db
from afterlife.collectors.base import Collector
from afterlife.models import Credential, Identity

API_BASE = "https://iam.googleapis.com/v1"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
SCOPE = "https://www.googleapis.com/auth/cloud-platform.read-only"


class GCPIAMCollector(Collector):
    source = "gcp"

    def __init__(
        self,
        db_path: Path,
        *,
        project: str,
        service_account_file: str | Path | None = None,
        access_token: str | None = None,
        api_url: str = API_BASE,
        token_endpoint: str = TOKEN_ENDPOINT,
    ):
        super().__init__(db_path)
        if not project:
            raise ValueError("GCPIAMCollector requires a project id")
        self.project = project
        self.service_account_file = service_account_file
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
        if not self.service_account_file:
            raise RuntimeError(
                "service_account_file is required when access_token is not provided"
            )
        sa = json.loads(Path(self.service_account_file).read_text())
        now = int(time.time())
        claims = {
            "iss": sa["client_email"],
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
            for sa in self._iter_service_accounts(client):
                db.upsert_identity(conn, self._sa_to_identity(sa))
                count += 1
                for key in self._iter_keys(client, sa["email"]):
                    db.upsert_credential(conn, self._key_to_credential(sa, key))
                    count += 1
        return count

    def _iter_service_accounts(
        self, client: httpx.Client
    ) -> Iterator[dict[str, Any]]:
        path = f"/projects/{self.project}/serviceAccounts"
        page_token: str | None = None
        while True:
            params: dict[str, Any] = {"pageSize": 100}
            if page_token:
                params["pageToken"] = page_token
            r = client.get(path, params=params)
            r.raise_for_status()
            data = r.json()
            yield from data.get("accounts", [])
            page_token = data.get("nextPageToken")
            if not page_token:
                return

    def _iter_keys(
        self, client: httpx.Client, sa_email: str
    ) -> Iterator[dict[str, Any]]:
        path = f"/projects/{self.project}/serviceAccounts/{sa_email}/keys"
        try:
            r = client.get(path, params={"keyTypes": "USER_MANAGED"})
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (403, 404):
                return
            raise
        yield from r.json().get("keys", [])

    def _sa_to_identity(self, sa: dict[str, Any]) -> Identity:
        status = "suspended" if sa.get("disabled") else "active"
        return Identity(
            source="gcp",
            source_id=sa["email"],
            email=sa["email"],
            name=sa.get("displayName") or sa["email"],
            status=status,
            last_seen=None,
            metadata={
                "project_id": sa.get("projectId"),
                "unique_id": sa.get("uniqueId"),
                "oauth2_client_id": sa.get("oauth2ClientId"),
                "disabled": sa.get("disabled"),
                "is_service_account": True,
            },
        )

    def _key_to_credential(
        self, sa: dict[str, Any], key: dict[str, Any]
    ) -> Credential:
        # Key name format: projects/PROJECT/serviceAccounts/SA_EMAIL/keys/KEY_ID
        key_id = key["name"].rsplit("/", 1)[-1]
        return Credential(
            source="gcp",
            credential_id=f"sa_key:{sa['email']}:{key_id}",
            credential_type="gcp_service_account_key",
            owner_source="gcp",
            owner_id=sa["email"],
            created_at=_parse_dt(key.get("validAfterTime")),
            last_used_at=None,
            scopes=[],
            is_active=True,
            metadata={
                "key_id": key_id,
                "key_algorithm": key.get("keyAlgorithm"),
                "key_type": key.get("keyType"),
                "key_origin": key.get("keyOrigin"),
                "valid_after_time": key.get("validAfterTime"),
                "valid_before_time": key.get("validBeforeTime"),
                "service_account_email": sa["email"],
            },
        )


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00"))
