"""Cross-source identity graph.

Builds a graph linking identities across systems (AWS, GitHub, IdP) by shared
correlation keys. v0.1 links by lowercased email only — login-equality and
fuzzy-name heuristics are deferred until we have a real false-positive corpus
to tune against.

Credentials are tracked per owner in a side map rather than as graph nodes;
the graph stays single-purpose (identity ↔ identity) which keeps queries
straightforward.

Cross-source rules query the graph to answer questions like "is this
credential's owner deprovisioned in any linked system?" (OFFBOARDED-OWNER).
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import networkx as nx

from afterlife import db
from afterlife.models import Credential, Identity


@dataclass
class Person:
    """A connected component in the identity graph — one human across systems."""

    identities: list[Identity]
    canonical_email: str | None = None

    @property
    def sources(self) -> set[str]:
        return {i.source for i in self.identities}

    @property
    def is_cross_source(self) -> bool:
        return len(self.sources) > 1

    def identity_in(self, source: str) -> Identity | None:
        for i in self.identities:
            if i.source == source:
                return i
        return None


class IdentityGraph:
    """NetworkX-backed graph of cross-source identity links.

    Nodes are `(source, source_id)` tuples. Edges represent same-person links,
    tagged with the heuristic that produced them (`kind="email"` for now).
    """

    def __init__(self) -> None:
        self.g: nx.Graph = nx.Graph()
        self._identities: dict[tuple[str, str], Identity] = {}
        self._creds_by_owner: dict[tuple[str, str], list[Credential]] = {}

    @classmethod
    def from_db(cls, db_path: Path) -> IdentityGraph:
        graph = cls()
        with db.connect(db_path) as conn:
            for row in conn.execute(
                "SELECT source, source_id, email, name, status, metadata "
                "FROM identities"
            ):
                graph._add_identity(_row_to_identity(row))
            for row in conn.execute(
                "SELECT source, credential_id, credential_type, owner_source, "
                "owner_id, scopes, is_active, metadata FROM credentials"
            ):
                cred = _row_to_credential(row)
                if cred.owner_source and cred.owner_id:
                    graph._creds_by_owner.setdefault(
                        (cred.owner_source, cred.owner_id), []
                    ).append(cred)
        graph._link_by_email()
        return graph

    def _add_identity(self, identity: Identity) -> None:
        key = (identity.source, identity.source_id)
        self.g.add_node(key)
        self._identities[key] = identity

    def _link_by_email(self) -> None:
        by_email: dict[str, list[tuple[str, str]]] = {}
        for key, identity in self._identities.items():
            if identity.email:
                by_email.setdefault(identity.email.lower(), []).append(key)
        for email, keys in by_email.items():
            if len(keys) < 2:
                continue
            for i, a in enumerate(keys):
                for b in keys[i + 1 :]:
                    self.g.add_edge(a, b, kind="email", email=email)

    def persons(self) -> Iterator[Person]:
        for component in nx.connected_components(self.g):
            yield self._make_person(component)

    def person_for(self, source: str, source_id: str) -> Person | None:
        key = (source, source_id)
        if key not in self._identities:
            return None
        component = nx.node_connected_component(self.g, key)
        return self._make_person(component)

    def credentials_for_person(self, person: Person) -> list[Credential]:
        creds: list[Credential] = []
        for identity in person.identities:
            key = (identity.source, identity.source_id)
            creds.extend(self._creds_by_owner.get(key, []))
        return creds

    def _make_person(self, keys) -> Person:
        identities = sorted(
            (self._identities[k] for k in keys),
            key=lambda i: i.source,
        )
        emails = {i.email.lower() for i in identities if i.email}
        return Person(
            identities=identities,
            canonical_email=sorted(emails)[0] if emails else None,
        )


def _row_to_identity(row: sqlite3.Row) -> Identity:
    return Identity(
        source=row["source"],
        source_id=row["source_id"],
        email=row["email"],
        name=row["name"],
        status=row["status"],
        last_seen=None,
        metadata=json.loads(row["metadata"]) if row["metadata"] else {},
    )


def _row_to_credential(row: sqlite3.Row) -> Credential:
    return Credential(
        source=row["source"],
        credential_id=row["credential_id"],
        credential_type=row["credential_type"],
        owner_source=row["owner_source"],
        owner_id=row["owner_id"],
        created_at=None,
        last_used_at=None,
        scopes=json.loads(row["scopes"]) if row["scopes"] else [],
        is_active=bool(row["is_active"]),
        metadata=json.loads(row["metadata"]) if row["metadata"] else {},
    )
