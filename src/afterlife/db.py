import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterator

from afterlife.models import Credential, Finding, Identity

SCHEMA = """
CREATE TABLE IF NOT EXISTS identities (
    source TEXT NOT NULL,
    source_id TEXT NOT NULL,
    email TEXT,
    name TEXT,
    status TEXT NOT NULL,
    last_seen TEXT,
    metadata TEXT,
    PRIMARY KEY (source, source_id)
);

CREATE TABLE IF NOT EXISTS credentials (
    source TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    credential_type TEXT NOT NULL,
    owner_source TEXT,
    owner_id TEXT,
    created_at TEXT,
    last_used_at TEXT,
    scopes TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    metadata TEXT,
    PRIMARY KEY (source, credential_id)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    identity_source TEXT,
    identity_id TEXT,
    evidence TEXT,
    suggested_remediation TEXT,
    blast_radius TEXT,
    suppressed INTEGER NOT NULL DEFAULT 0,
    suppression_reason TEXT,
    detected_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    records_collected INTEGER,
    error TEXT
);

CREATE INDEX IF NOT EXISTS idx_identities_email ON identities(email);
CREATE INDEX IF NOT EXISTS idx_credentials_owner ON credentials(owner_source, owner_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_scan_runs_started ON scan_runs(started_at);
"""


@contextmanager
def connect(path: Path) -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(path: Path) -> None:
    with connect(path) as conn:
        conn.executescript(SCHEMA)
        _migrate(conn)


def _migrate(conn: sqlite3.Connection) -> None:
    """Best-effort column additions for DBs created on older schema versions."""
    cols = {row[1] for row in conn.execute("PRAGMA table_info(findings)")}
    if "blast_radius" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN blast_radius TEXT")
    if "suppressed" not in cols:
        conn.execute(
            "ALTER TABLE findings ADD COLUMN suppressed INTEGER NOT NULL DEFAULT 0"
        )
    if "suppression_reason" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN suppression_reason TEXT")


def upsert_identity(conn: sqlite3.Connection, identity: Identity) -> None:
    conn.execute(
        """
        INSERT INTO identities (source, source_id, email, name, status, last_seen, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(source, source_id) DO UPDATE SET
            email = excluded.email,
            name = excluded.name,
            status = excluded.status,
            last_seen = excluded.last_seen,
            metadata = excluded.metadata
        """,
        (
            identity.source,
            identity.source_id,
            identity.email,
            identity.name,
            identity.status,
            _iso(identity.last_seen),
            json.dumps(identity.metadata),
        ),
    )


def upsert_credential(conn: sqlite3.Connection, cred: Credential) -> None:
    conn.execute(
        """
        INSERT INTO credentials (
            source, credential_id, credential_type, owner_source, owner_id,
            created_at, last_used_at, scopes, is_active, metadata
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(source, credential_id) DO UPDATE SET
            credential_type = excluded.credential_type,
            owner_source = excluded.owner_source,
            owner_id = excluded.owner_id,
            created_at = excluded.created_at,
            last_used_at = excluded.last_used_at,
            scopes = excluded.scopes,
            is_active = excluded.is_active,
            metadata = excluded.metadata
        """,
        (
            cred.source,
            cred.credential_id,
            cred.credential_type,
            cred.owner_source,
            cred.owner_id,
            _iso(cred.created_at),
            _iso(cred.last_used_at),
            json.dumps(cred.scopes),
            1 if cred.is_active else 0,
            json.dumps(cred.metadata),
        ),
    )


def insert_finding(conn: sqlite3.Connection, f: Finding) -> None:
    blast_json = None
    if f.blast_radius is not None:
        blast_json = json.dumps(
            {"score": f.blast_radius.score, "factors": f.blast_radius.factors}
        )
    conn.execute(
        """
        INSERT INTO findings (
            rule_id, severity, title, description,
            identity_source, identity_id, evidence,
            suggested_remediation, blast_radius,
            suppressed, suppression_reason, detected_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            f.rule_id,
            f.severity.value,
            f.title,
            f.description,
            f.identity_source,
            f.identity_id,
            json.dumps(f.evidence),
            f.suggested_remediation,
            blast_json,
            1 if f.suppressed else 0,
            f.suppression_reason,
            f.detected_at.isoformat(),
        ),
    )


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None
