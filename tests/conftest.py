from datetime import datetime, timezone
from pathlib import Path

import pytest

from afterlife import db
from afterlife.models import Credential, Identity


@pytest.fixture
def fresh_db(tmp_path: Path) -> Path:
    p = tmp_path / "test.db"
    db.init_db(p)
    return p


@pytest.fixture
def now() -> datetime:
    return datetime.now(timezone.utc)


def make_identity(**kw) -> Identity:
    defaults = dict(
        source="okta",
        source_id="user-1",
        email="user@example.com",
        name="Test User",
        status="active",
    )
    defaults.update(kw)
    return Identity(**defaults)


def make_credential(**kw) -> Credential:
    defaults = dict(
        source="aws",
        credential_id="AKIA-FAKE-1",
        credential_type="aws_access_key",
        owner_source="okta",
        owner_id="user-1",
    )
    defaults.update(kw)
    return Credential(**defaults)
