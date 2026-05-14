"""GitLab collector.

Pulls group members (including inherited members from parent groups) and
per-project deploy keys from one GitLab group. Auth is a Personal Access
Token sent in the `PRIVATE-TOKEN` header; pagination uses the standard
`Link: ...; rel="next"` header (same shape as GitHub, helper duplicated).

Group access tokens, project access tokens, and personal access tokens
require admin scopes that may not be available; this collector covers the
ground that any group-read PAT can reach.

Status mapping:
    state == "active"      -> "active"
    state == "blocked"     -> "suspended"
    state == "deactivated" -> "deprovisioned"
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterator
from urllib.parse import quote

import httpx

from afterlife import db
from afterlife.collectors.base import Collector
from afterlife.models import Credential, Identity

GITLAB_API = "https://gitlab.com/api/v4"

STATUS_MAP = {
    "active": "active",
    "blocked": "suspended",
    "deactivated": "deprovisioned",
    "ldap_blocked": "suspended",
    "banned": "deprovisioned",
}


class GitLabCollector(Collector):
    source = "gitlab"

    def __init__(
        self,
        db_path: Path,
        *,
        token: str,
        group: str,
        api_url: str = GITLAB_API,
    ):
        super().__init__(db_path)
        if not token:
            raise ValueError("GitLabCollector requires a token")
        if not group:
            raise ValueError("GitLabCollector requires a group path or id")
        self.token = token
        self.group = group
        self.api_url = api_url.rstrip("/")
        self._client: httpx.Client | None = None

    def run(self) -> int:
        owns = self._client is None
        if owns:
            self._client = httpx.Client(
                base_url=self.api_url,
                headers={
                    "PRIVATE-TOKEN": self.token,
                    "Accept": "application/json",
                    "User-Agent": "afterlife/0.1.0",
                },
                timeout=30.0,
            )
        try:
            return self._collect()
        finally:
            if owns and self._client is not None:
                self._client.close()
                self._client = None

    def _collect(self) -> int:
        group_id = quote(str(self.group), safe="")
        members = self._paginate(f"/groups/{group_id}/members/all")
        projects = self._paginate(
            f"/groups/{group_id}/projects",
            params={"include_subgroups": "true"},
        )

        count = 0
        with db.connect(self.db_path) as conn:
            for m in members:
                db.upsert_identity(conn, self._member_to_identity(m))
                count += 1
            for project in projects:
                keys = self._paginate(
                    f"/projects/{project['id']}/deploy_keys", optional=True
                )
                for key in keys:
                    db.upsert_credential(
                        conn, self._deploy_key_to_credential(project, key)
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

    def _member_to_identity(self, user: dict[str, Any]) -> Identity:
        state = (user.get("state") or "").lower()
        status = STATUS_MAP.get(state, "active")
        return Identity(
            source="gitlab",
            source_id=str(user["id"]),
            email=user.get("email"),
            name=user.get("name") or user.get("username"),
            status=status,
            last_seen=None,
            metadata={
                "username": user.get("username"),
                "access_level": user.get("access_level"),
                "expires_at": user.get("expires_at"),
                "state": user.get("state"),
                "web_url": user.get("web_url"),
            },
        )

    def _deploy_key_to_credential(
        self, project: dict[str, Any], key: dict[str, Any]
    ) -> Credential:
        return Credential(
            source="gitlab",
            credential_id=f"deploy_key:{project['path_with_namespace']}:{key['id']}",
            credential_type="gitlab_deploy_key",
            owner_source=None,
            owner_id=None,
            created_at=_parse_dt(key.get("created_at")),
            last_used_at=_parse_dt(key.get("last_used_at")),
            scopes=["push"] if key.get("can_push") else ["read"],
            is_active=True,
            metadata={
                "id": key["id"],
                "project": project["path_with_namespace"],
                "title": key.get("title"),
                "expires_at": key.get("expires_at"),
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


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00"))
