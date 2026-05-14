import json

import httpx
import pytest
import respx

from afterlife import db
from afterlife.collectors.azure_entra import AzureEntraIDCollector


def _user(uid, upn, *, enabled=True, mail=None, last_sign_in=None, display=None):
    return {
        "id": uid,
        "userPrincipalName": upn,
        "mail": mail or upn,
        "displayName": display or upn.split("@")[0],
        "accountEnabled": enabled,
        "createdDateTime": "2024-01-15T09:00:00Z",
        "signInActivity": (
            {"lastSignInDateTime": last_sign_in} if last_sign_in else None
        ),
    }


def _users_route():
    return respx.route(
        method="GET", host="graph.microsoft.com", path="/v1.0/users"
    )


def _run(fresh_db):
    return AzureEntraIDCollector(
        db_path=fresh_db, access_token="fake-token"
    ).run()


@respx.mock
def test_collects_active_user(fresh_db):
    _users_route().mock(
        return_value=httpx.Response(
            200, json={"value": [_user("u-1", "alice@contoso.com")]}
        )
    )

    _run(fresh_db)

    with db.connect(fresh_db) as conn:
        rows = conn.execute(
            "SELECT * FROM identities WHERE source = 'azure'"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["email"] == "alice@contoso.com"
        assert rows[0]["status"] == "active"
        assert rows[0]["source_id"] == "u-1"


@respx.mock
def test_disabled_account_maps_to_suspended(fresh_db):
    _users_route().mock(
        return_value=httpx.Response(
            200,
            json={"value": [_user("u-2", "bob@contoso.com", enabled=False)]},
        )
    )
    _run(fresh_db)
    with db.connect(fresh_db) as conn:
        row = conn.execute("SELECT status FROM identities").fetchone()
        assert row["status"] == "suspended"


@respx.mock
def test_paginates_via_nextlink(fresh_db):
    next_url = "https://graph.microsoft.com/v1.0/users?$skiptoken=abc"
    route = _users_route()
    route.side_effect = [
        httpx.Response(
            200,
            json={
                "value": [_user("u-1", "alice@contoso.com")],
                "@odata.nextLink": next_url,
            },
        ),
        httpx.Response(
            200, json={"value": [_user("u-2", "bob@contoso.com")]}
        ),
    ]
    _run(fresh_db)
    with db.connect(fresh_db) as conn:
        rows = conn.execute(
            "SELECT source_id FROM identities ORDER BY source_id"
        ).fetchall()
        assert [r["source_id"] for r in rows] == ["u-1", "u-2"]


@respx.mock
def test_last_sign_in_preserved_in_metadata(fresh_db):
    _users_route().mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    _user(
                        "u-1",
                        "alice@contoso.com",
                        last_sign_in="2026-05-01T10:00:00Z",
                    )
                ]
            },
        )
    )
    _run(fresh_db)
    with db.connect(fresh_db) as conn:
        row = conn.execute("SELECT metadata FROM identities").fetchone()
        meta = json.loads(row["metadata"])
        assert meta["last_login_time"] == "2026-05-01T10:00:00Z"


@respx.mock
def test_idempotent_rerun(fresh_db):
    _users_route().mock(
        return_value=httpx.Response(
            200, json={"value": [_user("u-1", "alice@contoso.com")]}
        )
    )
    _run(fresh_db)
    _run(fresh_db)
    with db.connect(fresh_db) as conn:
        n = conn.execute("SELECT COUNT(*) AS n FROM identities").fetchone()["n"]
        assert n == 1


@respx.mock
def test_empty_tenant(fresh_db):
    _users_route().mock(return_value=httpx.Response(200, json={"value": []}))
    assert _run(fresh_db) == 0


@respx.mock
def test_unauthorized_raises(fresh_db):
    _users_route().mock(
        return_value=httpx.Response(401, json={"error": {"message": "Unauthorized"}})
    )
    with pytest.raises(httpx.HTTPStatusError):
        _run(fresh_db)


@respx.mock
def test_full_oauth_flow_exchanges_client_credentials(fresh_db):
    """End-to-end auth path: POST to login.microsoftonline.com to get a
    token, then call Graph with that token."""
    respx.route(
        method="POST",
        host="login.microsoftonline.com",
        path="/test-tenant/oauth2/v2.0/token",
    ).mock(
        return_value=httpx.Response(
            200, json={"access_token": "issued-token", "expires_in": 3600}
        )
    )
    _users_route().mock(return_value=httpx.Response(200, json={"value": []}))

    AzureEntraIDCollector(
        db_path=fresh_db,
        tenant_id="test-tenant",
        client_id="client",
        client_secret="secret",
    ).run()

    last = respx.calls[-1].request
    assert last.url.path == "/v1.0/users"
    assert last.headers["authorization"] == "Bearer issued-token"


def test_constructor_without_token_or_credentials_at_least_records_state(fresh_db):
    """Constructing without auth params is allowed; the error surfaces only
    when run() needs to actually fetch a token."""
    c = AzureEntraIDCollector(db_path=fresh_db)
    assert c.access_token is None
    assert c.tenant_id is None
