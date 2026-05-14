"""Slack workspace collector.

Pulls Workspace members via `users.list` (Bearer-token auth). The collector
records humans, bots, app users, guests, and deleted members; downstream
rules differentiate them via metadata flags.

Status mapping:
    deleted: True         -> "deprovisioned"
    otherwise             -> "active"

Admin signals on the Slack identity (`is_admin`, `is_owner`,
`is_primary_owner`) flow into `metadata.is_admin` so ADMIN-CONCENTRATION
picks them up alongside other systems.

Slack is treated as an operational (downstream) source, not an IdP, so
ORPHANED-IDENTITY does not fire on Slack-only users.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterator

import httpx

from afterlife import db
from afterlife.collectors.base import Collector
from afterlife.models import Identity

API_BASE = "https://slack.com/api"


class SlackCollector(Collector):
    source = "slack"

    def __init__(
        self,
        db_path: Path,
        *,
        token: str,
        api_url: str = API_BASE,
    ):
        super().__init__(db_path)
        if not token:
            raise ValueError("SlackCollector requires a token")
        self.token = token
        self.api_url = api_url.rstrip("/")

    def run(self) -> int:
        with httpx.Client(
            base_url=self.api_url,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/json",
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
        cursor: str | None = None
        while True:
            params: dict[str, Any] = {"limit": 200}
            if cursor:
                params["cursor"] = cursor
            r = client.get("/users.list", params=params)
            r.raise_for_status()
            data = r.json()
            if not data.get("ok"):
                raise RuntimeError(
                    f"Slack API error: {data.get('error') or 'unknown'}"
                )
            yield from data.get("members", [])
            cursor = (data.get("response_metadata") or {}).get("next_cursor")
            if not cursor:
                return

    def _user_to_identity(self, user: dict[str, Any]) -> Identity:
        profile = user.get("profile") or {}
        deleted = bool(user.get("deleted"))
        is_bot = bool(user.get("is_bot") or user.get("is_app_user"))
        is_admin = bool(
            user.get("is_admin")
            or user.get("is_owner")
            or user.get("is_primary_owner")
        )
        return Identity(
            source="slack",
            source_id=user["id"],
            email=profile.get("email"),
            name=profile.get("real_name") or user.get("name"),
            status="deprovisioned" if deleted else "active",
            last_seen=None,
            metadata={
                "team_id": user.get("team_id"),
                "username": user.get("name"),
                "is_admin": is_admin,
                "is_owner": user.get("is_owner"),
                "is_primary_owner": user.get("is_primary_owner"),
                "is_bot": is_bot,
                "is_app_user": user.get("is_app_user"),
                "is_restricted": user.get("is_restricted"),
                "is_ultra_restricted": user.get("is_ultra_restricted"),
                "is_guest": bool(
                    user.get("is_restricted")
                    or user.get("is_ultra_restricted")
                ),
            },
        )
