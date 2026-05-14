"""HashiCorp Vault collector: entities + their cross-system aliases.

Vault's identity store already represents the same concept Afterlife builds
elsewhere (one human, multiple linked external principals). Each Vault
`entity` has zero or more `aliases`, each of which names a principal in
another system (an AWS IAM ARN, a GitHub login, an OIDC subject, etc.).

This collector stores Vault entities as Identity rows (source="vault") and
records each entity's aliases in metadata. The identity-graph layer reads
those aliases on graph build to create direct vault->aws / vault->github
edges, so a Vault-linked person crosses to AWS even without a matching
email.

Token enumeration via /v1/auth/token/accessors is intentionally not
covered: it requires sudo-tier policy and most v0.1 audit users won't
have it. The collector graceful-degrades on 403 from the alias-detail
calls so it still produces value with a read-only entity-list policy.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

import httpx

from afterlife import db
from afterlife.collectors.base import Collector
from afterlife.models import Identity


class VaultCollector(Collector):
    source = "vault"

    def __init__(
        self,
        db_path: Path,
        *,
        token: str,
        api_url: str,
        namespace: str | None = None,
    ):
        super().__init__(db_path)
        if not token:
            raise ValueError("VaultCollector requires a token")
        if not api_url:
            raise ValueError("VaultCollector requires an api_url")
        self.token = token
        self.api_url = api_url.rstrip("/")
        self.namespace = namespace

    def run(self) -> int:
        headers = {
            "X-Vault-Token": self.token,
            "Accept": "application/json",
        }
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        with httpx.Client(
            base_url=self.api_url, headers=headers, timeout=30.0
        ) as client:
            return self._collect(client)

    def _collect(self, client: httpx.Client) -> int:
        count = 0
        with db.connect(self.db_path) as conn:
            for entity in self._iter_entities(client):
                db.upsert_identity(conn, self._entity_to_identity(entity))
                count += 1
        return count

    def _iter_entities(self, client: httpx.Client) -> Iterator[dict[str, Any]]:
        # Vault uses LIST semantically; the documented portable form is GET
        # with ?list=true. Pagination is not supported on this endpoint;
        # very large deployments would need a different strategy.
        ids = self._list_entity_ids(client)
        for eid in ids:
            entity = self._get_entity(client, eid)
            if entity is not None:
                yield entity

    def _list_entity_ids(self, client: httpx.Client) -> list[str]:
        r = client.get("/v1/identity/entity/id", params={"list": "true"})
        if r.status_code == 404:
            return []
        r.raise_for_status()
        data = r.json() or {}
        return list((data.get("data") or {}).get("keys") or [])

    def _get_entity(
        self, client: httpx.Client, entity_id: str
    ) -> dict[str, Any] | None:
        try:
            r = client.get(f"/v1/identity/entity/id/{entity_id}")
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            # Some entities may be permission-restricted even for token holders
            # with a list policy. Skip rather than abort the whole run.
            if e.response.status_code in (403, 404):
                return None
            raise
        return ((r.json() or {}).get("data")) or None

    def _entity_to_identity(self, entity: dict[str, Any]) -> Identity:
        # Vault entity metadata is an arbitrary KV map. If the operator put an
        # email in there, surface it for cross-source email linking too.
        ent_meta = entity.get("metadata") or {}
        email = ent_meta.get("email") if isinstance(ent_meta, dict) else None
        aliases = [
            {
                "id": a.get("id"),
                "mount_type": a.get("mount_type"),
                "mount_path": a.get("mount_path"),
                "name": a.get("name"),
            }
            for a in entity.get("aliases") or []
        ]
        return Identity(
            source="vault",
            source_id=str(entity["id"]),
            email=email,
            name=entity.get("name") or str(entity["id"]),
            status="active",
            last_seen=None,
            metadata={
                "entity_id": entity["id"],
                "vault_metadata": ent_meta,
                "aliases": aliases,
                "creation_time": entity.get("creation_time"),
                "last_update_time": entity.get("last_update_time"),
            },
        )


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
