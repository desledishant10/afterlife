import json

import httpx
import pytest
import respx

from afterlife import db
from afterlife.collectors.slack import SlackCollector


def _user(uid, name, email=None, **kw):
    base = {
        "id": uid,
        "team_id": "T-DEMO",
        "name": name,
        "real_name": name,
        "profile": {
            "email": email,
            "real_name": name,
            "display_name": name,
        },
        "deleted": False,
        "is_admin": False,
        "is_owner": False,
        "is_primary_owner": False,
        "is_restricted": False,
        "is_ultra_restricted": False,
        "is_bot": False,
        "is_app_user": False,
    }
    base.update(kw)
    return base


def _route():
    return respx.route(method="GET", host="slack.com", path="/api/users.list")


def _run(fresh_db):
    return SlackCollector(db_path=fresh_db, token="xoxb-fake").run()


@respx.mock
def test_collects_active_user(fresh_db):
    _route().mock(
        return_value=httpx.Response(
            200,
            json={
                "ok": True,
                "members": [_user("U1", "alice", "alice@example.com")],
            },
        )
    )
    _run(fresh_db)
    with db.connect(fresh_db) as conn:
        row = conn.execute(
            "SELECT * FROM identities WHERE source = 'slack'"
        ).fetchone()
        assert row is not None
        assert row["email"] == "alice@example.com"
        assert row["status"] == "active"
        assert row["source_id"] == "U1"


@respx.mock
def test_deleted_user_maps_to_deprovisioned(fresh_db):
    _route().mock(
        return_value=httpx.Response(
            200,
            json={
                "ok": True,
                "members": [
                    _user("U2", "ex", "ex@example.com", deleted=True)
                ],
            },
        )
    )
    _run(fresh_db)
    with db.connect(fresh_db) as conn:
        row = conn.execute("SELECT status FROM identities").fetchone()
        assert row["status"] == "deprovisioned"


@respx.mock
def test_admin_flag_surfaces_in_metadata(fresh_db):
    _route().mock(
        return_value=httpx.Response(
            200,
            json={
                "ok": True,
                "members": [
                    _user("U3", "boss", "boss@example.com", is_admin=True)
                ],
            },
        )
    )
    _run(fresh_db)
    with db.connect(fresh_db) as conn:
        row = conn.execute("SELECT metadata FROM identities").fetchone()
        meta = json.loads(row["metadata"])
        assert meta["is_admin"] is True


@respx.mock
def test_bot_user_flagged_in_metadata(fresh_db):
    _route().mock(
        return_value=httpx.Response(
            200,
            json={
                "ok": True,
                "members": [_user("B1", "ci-bot", is_bot=True)],
            },
        )
    )
    _run(fresh_db)
    with db.connect(fresh_db) as conn:
        row = conn.execute("SELECT metadata FROM identities").fetchone()
        meta = json.loads(row["metadata"])
        assert meta["is_bot"] is True


@respx.mock
def test_guest_flagged_in_metadata(fresh_db):
    _route().mock(
        return_value=httpx.Response(
            200,
            json={
                "ok": True,
                "members": [
                    _user("G1", "external", is_restricted=True)
                ],
            },
        )
    )
    _run(fresh_db)
    with db.connect(fresh_db) as conn:
        row = conn.execute("SELECT metadata FROM identities").fetchone()
        meta = json.loads(row["metadata"])
        assert meta["is_guest"] is True
        assert meta["is_restricted"] is True


@respx.mock
def test_paginates_via_next_cursor(fresh_db):
    route = _route()
    route.side_effect = [
        httpx.Response(
            200,
            json={
                "ok": True,
                "members": [_user("U1", "alice")],
                "response_metadata": {"next_cursor": "abc"},
            },
        ),
        httpx.Response(
            200,
            json={
                "ok": True,
                "members": [_user("U2", "bob")],
                "response_metadata": {"next_cursor": ""},
            },
        ),
    ]
    _run(fresh_db)
    with db.connect(fresh_db) as conn:
        n = conn.execute("SELECT COUNT(*) AS n FROM identities").fetchone()["n"]
        assert n == 2


@respx.mock
def test_api_ok_false_raises(fresh_db):
    _route().mock(
        return_value=httpx.Response(
            200, json={"ok": False, "error": "invalid_auth"}
        )
    )
    with pytest.raises(RuntimeError, match="invalid_auth"):
        _run(fresh_db)


@respx.mock
def test_rerun_is_idempotent(fresh_db):
    _route().mock(
        return_value=httpx.Response(
            200, json={"ok": True, "members": [_user("U1", "alice")]}
        )
    )
    _run(fresh_db)
    _run(fresh_db)
    with db.connect(fresh_db) as conn:
        n = conn.execute("SELECT COUNT(*) AS n FROM identities").fetchone()["n"]
        assert n == 1


def test_constructor_requires_token(fresh_db):
    with pytest.raises(ValueError, match="token"):
        SlackCollector(db_path=fresh_db, token="")
