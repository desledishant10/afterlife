import json

import httpx
import pytest
import respx

from afterlife import db
from afterlife.collectors.vault import VaultCollector

VAULT = "https://vault.example.com:8200"


def _entity(eid, name, aliases=None, metadata=None):
    return {
        "id": eid,
        "name": name,
        "creation_time": "2024-01-15T09:00:00Z",
        "last_update_time": "2024-06-01T12:00:00Z",
        "aliases": aliases or [],
        "metadata": metadata or {},
    }


def _list_route():
    return respx.route(
        method="GET", host="vault.example.com", path="/v1/identity/entity/id"
    )


def _detail_route(eid):
    return respx.route(
        method="GET",
        host="vault.example.com",
        path=f"/v1/identity/entity/id/{eid}",
    )


def _run(fresh_db):
    return VaultCollector(
        db_path=fresh_db, token="hvs.fake-token", api_url=VAULT
    ).run()


@respx.mock
def test_collects_entity(fresh_db):
    _list_route().mock(
        return_value=httpx.Response(200, json={"data": {"keys": ["ent-1"]}})
    )
    _detail_route("ent-1").mock(
        return_value=httpx.Response(
            200,
            json={"data": _entity("ent-1", "alice", metadata={"email": "alice@example.com"})},
        )
    )

    _run(fresh_db)

    with db.connect(fresh_db) as conn:
        row = conn.execute(
            "SELECT * FROM identities WHERE source = 'vault'"
        ).fetchone()
        assert row is not None
        assert row["source_id"] == "ent-1"
        assert row["name"] == "alice"
        assert row["email"] == "alice@example.com"


@respx.mock
def test_aliases_stored_in_metadata(fresh_db):
    _list_route().mock(
        return_value=httpx.Response(200, json={"data": {"keys": ["ent-1"]}})
    )
    aliases = [
        {
            "id": "alias-aws",
            "mount_type": "aws",
            "mount_path": "aws/",
            "name": "arn:aws:iam::123456789012:user/alice",
        },
        {
            "id": "alias-gh",
            "mount_type": "github",
            "mount_path": "github/",
            "name": "alice",
        },
    ]
    _detail_route("ent-1").mock(
        return_value=httpx.Response(
            200, json={"data": _entity("ent-1", "alice", aliases=aliases)}
        )
    )

    _run(fresh_db)

    with db.connect(fresh_db) as conn:
        row = conn.execute("SELECT metadata FROM identities").fetchone()
        meta = json.loads(row["metadata"])
        assert len(meta["aliases"]) == 2
        mount_types = {a["mount_type"] for a in meta["aliases"]}
        assert mount_types == {"aws", "github"}


@respx.mock
def test_multiple_entities(fresh_db):
    _list_route().mock(
        return_value=httpx.Response(
            200, json={"data": {"keys": ["ent-1", "ent-2"]}}
        )
    )
    _detail_route("ent-1").mock(
        return_value=httpx.Response(200, json={"data": _entity("ent-1", "alice")})
    )
    _detail_route("ent-2").mock(
        return_value=httpx.Response(200, json={"data": _entity("ent-2", "bob")})
    )
    _run(fresh_db)
    with db.connect(fresh_db) as conn:
        n = conn.execute("SELECT COUNT(*) AS n FROM identities").fetchone()["n"]
        assert n == 2


@respx.mock
def test_empty_entity_list_returns_zero(fresh_db):
    _list_route().mock(
        return_value=httpx.Response(200, json={"data": {"keys": []}})
    )
    assert _run(fresh_db) == 0


@respx.mock
def test_list_endpoint_404_returns_zero(fresh_db):
    """Vault returns 404 when there are no entities (some versions)."""
    _list_route().mock(return_value=httpx.Response(404))
    assert _run(fresh_db) == 0


@respx.mock
def test_per_entity_403_is_non_fatal(fresh_db):
    _list_route().mock(
        return_value=httpx.Response(
            200, json={"data": {"keys": ["ent-1", "ent-2"]}}
        )
    )
    _detail_route("ent-1").mock(
        return_value=httpx.Response(403, json={"errors": ["permission denied"]})
    )
    _detail_route("ent-2").mock(
        return_value=httpx.Response(200, json={"data": _entity("ent-2", "bob")})
    )
    _run(fresh_db)
    with db.connect(fresh_db) as conn:
        rows = conn.execute("SELECT name FROM identities").fetchall()
        assert len(rows) == 1
        assert rows[0]["name"] == "bob"


@respx.mock
def test_unauthorized_raises(fresh_db):
    _list_route().mock(
        return_value=httpx.Response(401, json={"errors": ["invalid token"]})
    )
    with pytest.raises(httpx.HTTPStatusError):
        _run(fresh_db)


@respx.mock
def test_rerun_is_idempotent(fresh_db):
    _list_route().mock(
        return_value=httpx.Response(200, json={"data": {"keys": ["ent-1"]}})
    )
    _detail_route("ent-1").mock(
        return_value=httpx.Response(200, json={"data": _entity("ent-1", "alice")})
    )
    _run(fresh_db)
    _run(fresh_db)
    with db.connect(fresh_db) as conn:
        n = conn.execute("SELECT COUNT(*) AS n FROM identities").fetchone()["n"]
        assert n == 1


@respx.mock
def test_namespace_header_sent_when_provided(fresh_db):
    _list_route().mock(return_value=httpx.Response(200, json={"data": {"keys": []}}))
    VaultCollector(
        db_path=fresh_db,
        token="t",
        api_url=VAULT,
        namespace="team-platform/",
    ).run()
    assert respx.calls[-1].request.headers["x-vault-namespace"] == "team-platform/"


def test_constructor_requires_token(fresh_db):
    with pytest.raises(ValueError, match="token"):
        VaultCollector(db_path=fresh_db, token="", api_url=VAULT)


def test_constructor_requires_api_url(fresh_db):
    with pytest.raises(ValueError, match="api_url"):
        VaultCollector(db_path=fresh_db, token="t", api_url="")
