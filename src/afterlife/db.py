import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from afterlife.models import Credential, Finding, Identity, finding_fingerprint

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
    detected_at TEXT NOT NULL,
    fingerprint TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    first_seen TEXT,
    last_seen TEXT,
    resolved_at TEXT
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
    """Best-effort column additions for DBs created on older schema versions.

    Runs after the CREATE TABLE / CREATE INDEX script. The finding-lifecycle
    columns and their indexes are created here (not in SCHEMA) because they
    reference columns that older databases do not yet have; adding the columns
    first keeps the index creation valid on upgrade.
    """
    cols = {row[1] for row in conn.execute("PRAGMA table_info(findings)")}
    if "blast_radius" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN blast_radius TEXT")
    if "suppressed" not in cols:
        conn.execute(
            "ALTER TABLE findings ADD COLUMN suppressed INTEGER NOT NULL DEFAULT 0"
        )
    if "suppression_reason" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN suppression_reason TEXT")
    if "fingerprint" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN fingerprint TEXT")
    if "status" not in cols:
        conn.execute(
            "ALTER TABLE findings ADD COLUMN status TEXT NOT NULL DEFAULT 'open'"
        )
    if "first_seen" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN first_seen TEXT")
    if "last_seen" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN last_seen TEXT")
    if "resolved_at" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN resolved_at TEXT")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status)"
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS "
        "idx_findings_fingerprint ON findings(fingerprint)"
    )


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


def _blast_json(f: Finding) -> str | None:
    if f.blast_radius is None:
        return None
    return json.dumps(
        {"score": f.blast_radius.score, "factors": f.blast_radius.factors}
    )


def insert_finding(conn: sqlite3.Connection, f: Finding) -> None:
    """Insert a single finding as open, seeding its lifecycle fields.

    Used for direct seeding (and tests). The analyze path uses
    `reconcile_findings`, which tracks findings across runs instead.
    """
    detected = f.detected_at.isoformat()
    conn.execute(
        """
        INSERT INTO findings (
            rule_id, severity, title, description,
            identity_source, identity_id, evidence,
            suggested_remediation, blast_radius,
            suppressed, suppression_reason, detected_at,
            fingerprint, status, first_seen, last_seen, resolved_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, NULL)
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
            _blast_json(f),
            1 if f.suppressed else 0,
            f.suppression_reason,
            detected,
            finding_fingerprint(f),
            detected,
            detected,
        ),
    )


@dataclass
class ReconcileSummary:
    """Deltas from one analyze run relative to the stored finding history."""

    new: int = 0
    reopened: int = 0
    ongoing: int = 0
    resolved: int = 0
    open_total: int = 0
    new_fingerprints: set[str] = field(default_factory=set)
    reopened_fingerprints: set[str] = field(default_factory=set)

    @property
    def changed_fingerprints(self) -> set[str]:
        """Fingerprints that appeared or reappeared this run (worth alerting)."""
        return self.new_fingerprints | self.reopened_fingerprints


def reconcile_findings(
    conn: sqlite3.Connection, findings: list[Finding], now: datetime
) -> ReconcileSummary:
    """Reconcile a freshly computed finding set against stored history.

    Rather than deleting and re-inserting, each finding is matched by
    fingerprint: unseen becomes `new`, a previously-resolved fingerprint that
    reappears becomes `reopened`, and an already-open one is `ongoing`. Stored
    open findings whose fingerprint is absent from the new set are marked
    `resolved` (kept in the table, not deleted). Returns the deltas so callers
    can report what changed since the last scan.
    """
    now_iso = now.isoformat()
    prior = {
        row["fingerprint"]: row["status"]
        for row in conn.execute(
            "SELECT fingerprint, status FROM findings WHERE fingerprint IS NOT NULL"
        )
    }
    summary = ReconcileSummary()
    current_fps: list[str] = []
    for f in findings:
        fp = finding_fingerprint(f)
        current_fps.append(fp)
        prev = prior.get(fp)
        if prev is None:
            summary.new += 1
            summary.new_fingerprints.add(fp)
        elif prev == "resolved":
            summary.reopened += 1
            summary.reopened_fingerprints.add(fp)
        else:
            summary.ongoing += 1
        _upsert_finding(conn, f, fp, now_iso)
    summary.resolved = _resolve_absent(conn, current_fps, now_iso)
    summary.open_total = conn.execute(
        "SELECT COUNT(*) AS n FROM findings WHERE status = 'open'"
    ).fetchone()["n"]
    return summary


def _upsert_finding(
    conn: sqlite3.Connection, f: Finding, fingerprint: str, now_iso: str
) -> None:
    conn.execute(
        """
        INSERT INTO findings (
            rule_id, severity, title, description,
            identity_source, identity_id, evidence,
            suggested_remediation, blast_radius,
            suppressed, suppression_reason, detected_at,
            fingerprint, status, first_seen, last_seen, resolved_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, NULL)
        ON CONFLICT(fingerprint) DO UPDATE SET
            severity = excluded.severity,
            title = excluded.title,
            description = excluded.description,
            identity_source = excluded.identity_source,
            identity_id = excluded.identity_id,
            evidence = excluded.evidence,
            suggested_remediation = excluded.suggested_remediation,
            blast_radius = excluded.blast_radius,
            suppressed = excluded.suppressed,
            suppression_reason = excluded.suppression_reason,
            status = 'open',
            last_seen = excluded.last_seen,
            resolved_at = NULL
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
            _blast_json(f),
            1 if f.suppressed else 0,
            f.suppression_reason,
            now_iso,
            fingerprint,
            now_iso,
            now_iso,
        ),
    )


def _resolve_absent(
    conn: sqlite3.Connection, current_fps: list[str], now_iso: str
) -> int:
    if current_fps:
        placeholders = ",".join("?" * len(current_fps))
        cur = conn.execute(
            f"UPDATE findings SET status = 'resolved', resolved_at = ? "
            f"WHERE status = 'open' "
            f"AND (fingerprint IS NULL OR fingerprint NOT IN ({placeholders}))",
            [now_iso, *current_fps],
        )
    else:
        cur = conn.execute(
            "UPDATE findings SET status = 'resolved', resolved_at = ? "
            "WHERE status = 'open'",
            (now_iso,),
        )
    return cur.rowcount


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None
