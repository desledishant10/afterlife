import json

import httpx
import pytest
import respx

from afterlife import db
from afterlife.collectors.okta import OktaCollector

OKTA_HOST = "testorg.okta.com"


def _user(uid: str, email: str, *, status: str = "ACTIVE",
          first: str = "First", last: str = "Last") -> dict:
    return {
        "id": uid,
        "status": status,
        "created": "2024-01-01T00:00:00.000Z",
        "activated": "2024-01-01T00:30:00.000Z",
        "lastLogin": "2026-05-01T10:00:00.000Z",
        "profile": {
            "firstName": first,
            "lastName": last,
            "email": email,
            "login": email,
        },
    }


def _users_route():
    return respx.route(method="GET", host=OKTA_HOST, path="/api/v1/users")


def _run(fresh_db):
    return OktaCollector(
        db_path=fresh_db, domain=OKTA_HOST, api_token="fake-token"
    ).run()


@respx.mock
def test_collects_active_user(fresh_db):
    _users_route().mock(
        return_value=httpx.Response(200, json=[_user("00u1", "alice@example.com")])
    )

    _run(fresh_db)

    with db.connect(fresh_db) as conn:
        rows = conn.execute(
            "SELECT * FROM identities WHERE source = 'okta'"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["email"] == "alice@example.com"
        assert rows[0]["status"] == "active"
        assert rows[0]["name"] == "First Last"


@respx.mock
def test_suspended_status_mapped(fresh_db):
    _users_route().mock(
        return_value=httpx.Response(
            200, json=[_user("00u2", "bob@example.com", status="SUSPENDED")]
        )
    )
    _run(fresh_db)
    with db.connect(fresh_db) as conn:
        row = conn.execute("SELECT status FROM identities").fetchone()
        assert row["status"] == "suspended"


@respx.mock
def test_deprovisioned_status_mapped(fresh_db):
    _users_route().mock(
        return_value=httpx.Response(
            200, json=[_user("00u3", "carol@example.com", status="DEPROVISIONED")]
        )
    )
    _run(fresh_db)
    with db.connect(fresh_db) as conn:
        row = conn.execute("SELECT status FROM identities").fetchone()
        assert row["status"] == "deprovisioned"


@respx.mock
def test_locked_out_treated_as_active(fresh_db):
    """LOCKED_OUT is recoverable; it should not fire OFFBOARDED-OWNER."""
    _users_route().mock(
        return_value=httpx.Response(
            200, json=[_user("00u4", "dave@example.com", status="LOCKED_OUT")]
        )
    )
    _run(fresh_db)
    with db.connect(fresh_db) as conn:
        row = conn.execute("SELECT status FROM identities").fetchone()
        assert row["status"] == "active"


@respx.mock
def test_staged_status_mapped(fresh_db):
    _users_route().mock(
        return_value=httpx.Response(
            200, json=[_user("00u5", "newhire@example.com", status="STAGED")]
        )
    )
    _run(fresh_db)
    with db.connect(fresh_db) as conn:
        row = conn.execute("SELECT status FROM identities").fetchone()
        assert row["status"] == "staged"


@respx.mock
def test_paginates_via_link_header(fresh_db):
    next_url = f"https://{OKTA_HOST}/api/v1/users?after=00u1"
    route = _users_route()
    route.side_effect = [
        httpx.Response(
            200,
            json=[_user("00u1", "alice@example.com")],
            headers={"Link": f'<{next_url}>; rel="next"'},
        ),
        httpx.Response(200, json=[_user("00u2", "bob@example.com")]),
    ]

    _run(fresh_db)

    with db.connect(fresh_db) as conn:
        ids = conn.execute(
            "SELECT source_id FROM identities ORDER BY source_id"
        ).fetchall()
        assert [r["source_id"] for r in ids] == ["00u1", "00u2"]


@respx.mock
def test_rerun_is_idempotent(fresh_db):
    _users_route().mock(
        return_value=httpx.Response(200, json=[_user("00u1", "alice@example.com")])
    )
    _run(fresh_db)
    _run(fresh_db)
    with db.connect(fresh_db) as conn:
        n = conn.execute("SELECT COUNT(*) AS n FROM identities").fetchone()["n"]
        assert n == 1


@respx.mock
def test_empty_org(fresh_db):
    _users_route().mock(return_value=httpx.Response(200, json=[]))
    assert _run(fresh_db) == 0


@respx.mock
def test_unauthorized_raises(fresh_db):
    _users_route().mock(
        return_value=httpx.Response(401, json={"errorCode": "E0000011"})
    )
    with pytest.raises(httpx.HTTPStatusError):
        _run(fresh_db)


@respx.mock
def test_okta_status_preserved_in_metadata(fresh_db):
    _users_route().mock(
        return_value=httpx.Response(
            200,
            json=[_user("00u1", "alice@example.com", status="PASSWORD_EXPIRED")],
        )
    )
    _run(fresh_db)
    with db.connect(fresh_db) as conn:
        row = conn.execute(
            "SELECT status, metadata FROM identities"
        ).fetchone()
        assert row["status"] == "active"
        meta = json.loads(row["metadata"])
        assert meta["okta_status"] == "PASSWORD_EXPIRED"


def test_constructor_requires_token(fresh_db):
    with pytest.raises(ValueError, match="api_token"):
        OktaCollector(db_path=fresh_db, domain="testorg.okta.com")


def test_constructor_requires_domain_or_api_url(fresh_db):
    with pytest.raises(ValueError, match="domain or api_url"):
        OktaCollector(db_path=fresh_db, api_token="x")
