from datetime import datetime
from pathlib import Path
from typing import Any, Callable

import httpx

from afterlife import db
from afterlife.collectors.base import Collector
from afterlife.models import Credential, Identity

GH_API = "https://api.github.com"


class GitHubCollector(Collector):
    """Pulls org members, outside collaborators, GitHub App installations, and
    per-repo deploy keys from one GitHub organization.

    Personal Access Tokens are intentionally out of scope: the public REST API
    does not expose them at the org level, and the Enterprise SAML SSO endpoint
    (`/orgs/{org}/credential-authorizations`) requires Enterprise tier.
    """

    source = "github"

    def __init__(
        self,
        token: str,
        org: str,
        db_path: Path,
        *,
        api_url: str = GH_API,
    ):
        super().__init__(db_path)
        self.token = token
        self.org = org
        self.api_url = api_url.rstrip("/")
        self._client: httpx.Client | None = None

    def run(self) -> int:
        owns_client = self._client is None
        if owns_client:
            self._client = self._make_client()
        try:
            return self._collect()
        finally:
            if owns_client and self._client is not None:
                self._client.close()
                self._client = None

    def _make_client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.api_url,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "afterlife/0.1.0",
            },
            timeout=30.0,
        )

    def _collect(self) -> int:
        members = self._paginate(f"/orgs/{self.org}/members")
        outside = self._paginate(f"/orgs/{self.org}/outside_collaborators")
        installs = self._paginate(
            f"/orgs/{self.org}/installations",
            extract=lambda r: r.json().get("installations", []),
            optional=True,
        )
        repos = self._paginate(
            f"/orgs/{self.org}/repos", params={"type": "all"}
        )

        count = 0
        with db.connect(self.db_path) as conn:
            for user in members:
                db.upsert_identity(conn, self._user_to_identity(user, is_outside=False))
                count += 1
            for user in outside:
                db.upsert_identity(conn, self._user_to_identity(user, is_outside=True))
                count += 1
            for install in installs:
                db.upsert_credential(conn, self._installation_to_credential(install))
                count += 1
            for repo in repos:
                # Repos we can't read keys for (private, no admin scope) 404 silently.
                keys = self._paginate(
                    f"/repos/{repo['full_name']}/keys", optional=True
                )
                for key in keys:
                    db.upsert_credential(
                        conn, self._deploy_key_to_credential(repo, key)
                    )
                    count += 1
        return count

    def _paginate(
        self,
        path: str,
        *,
        params: dict | None = None,
        extract: Callable[[httpx.Response], list[dict]] | None = None,
        optional: bool = False,
    ) -> list[dict]:
        items: list[dict] = []
        url: str | None = path
        request_params = dict(params or {})
        request_params.setdefault("per_page", 100)
        first = True
        extract_fn = extract or (lambda r: r.json())

        assert self._client is not None
        while url:
            try:
                r = self._client.get(
                    url, params=request_params if first else None
                )
                r.raise_for_status()
            except httpx.HTTPStatusError as e:
                if optional and e.response.status_code in (403, 404):
                    return items
                raise
            items.extend(extract_fn(r))
            url = _parse_link_next(r.headers.get("Link", ""))
            first = False
        return items

    def _user_to_identity(self, user: dict[str, Any], is_outside: bool) -> Identity:
        return Identity(
            source="github",
            source_id=user["login"],
            email=user.get("email"),
            name=user.get("name") or user["login"],
            status="active",
            last_seen=None,
            metadata={
                "id": user.get("id"),
                "type": user.get("type"),
                "is_outside_collaborator": is_outside,
                "html_url": user.get("html_url"),
            },
        )

    def _installation_to_credential(self, install: dict[str, Any]) -> Credential:
        permissions = install.get("permissions") or {}
        return Credential(
            source="github",
            credential_id=f"installation:{install['id']}",
            credential_type="github_app_installation",
            owner_source=None,
            owner_id=None,
            created_at=_parse_dt(install.get("created_at")),
            last_used_at=None,
            scopes=sorted(permissions.keys()),
            is_active=True,
            metadata={
                "id": install["id"],
                "app_slug": install.get("app_slug"),
                "permissions": permissions,
                "events": install.get("events"),
            },
        )

    def _deploy_key_to_credential(
        self, repo: dict[str, Any], key: dict[str, Any]
    ) -> Credential:
        return Credential(
            source="github",
            credential_id=f"deploy_key:{repo['full_name']}:{key['id']}",
            credential_type="github_deploy_key",
            owner_source=None,
            owner_id=None,
            created_at=_parse_dt(key.get("created_at")),
            last_used_at=_parse_dt(key.get("last_used")),
            scopes=["read"] if key.get("read_only") else ["read", "write"],
            is_active=True,
            metadata={
                "id": key["id"],
                "repo": repo["full_name"],
                "title": key.get("title"),
                "verified": key.get("verified"),
            },
        )


def _parse_link_next(link_header: str) -> str | None:
    if not link_header:
        return None
    for part in link_header.split(","):
        part = part.strip()
        if 'rel="next"' in part:
            url_part = part.split(";")[0].strip()
            return url_part.strip("<>")
    return None


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00"))
