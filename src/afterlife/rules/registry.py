import importlib
import json
import pkgutil
from datetime import datetime
from pathlib import Path

from afterlife import db
from afterlife.allowlist import Suppression, apply_suppressions, load_allowlist
from afterlife.config import DEFAULT, Config
from afterlife.graph.identity_graph import IdentityGraph
from afterlife.models import Credential, Finding, Severity
from afterlife.rules.base import Rule
from afterlife.scoring.blast_radius import score as score_credential

_RULES: list[Rule] = []


def rule(
    *,
    id: str,
    title: str,
    description: str,
    severity: Severity,
):
    """Decorator that registers a function as a detection rule.

    The wrapped function takes (sqlite_conn, config, graph) and returns
    list[Finding]. Rules that do not need the identity graph still accept
    the parameter; uniform signature keeps the registry simple.
    """

    def decorator(fn):
        _RULES.append(
            Rule(
                id=id,
                title=title,
                description=description,
                default_severity=severity,
                evaluate=fn,
            )
        )
        return fn

    return decorator


def _discover() -> None:
    import afterlife.rules as pkg

    for mod in pkgutil.iter_modules(pkg.__path__):
        if mod.name not in {"base", "registry"}:
            importlib.import_module(f"afterlife.rules.{mod.name}")


def all_rules() -> list[Rule]:
    if not _RULES:
        _discover()
    return list(_RULES)


def run_all(
    db_path: Path,
    config: Config = DEFAULT,
    *,
    allowlist_path: Path | None = None,
) -> list[Finding]:
    all_rules()
    suppressions = load_allowlist(allowlist_path) if allowlist_path else []
    today = datetime.utcnow().date()
    active_suppressions = [s for s in suppressions if s.is_active(today)]

    findings: list[Finding] = []
    with db.connect(db_path) as conn:
        # analyze replaces the prior finding set; we don't accumulate history
        # in this table. Scan-run history lives in scan_runs.
        conn.execute("DELETE FROM findings")
        graph = IdentityGraph.from_conn(conn)
        credential_index = _load_credential_index(conn)
        for r in _RULES:
            for f in r.evaluate(conn, config, graph):
                cred = _find_credential(f, credential_index)
                if cred is not None:
                    f.blast_radius = score_credential(cred)
                for s in active_suppressions:
                    if s.matches(f):
                        f.suppressed = True
                        f.suppression_reason = s.reason or "suppressed"
                        break
                db.insert_finding(conn, f)
                findings.append(f)
    return findings


def _load_credential_index(conn) -> dict[str, Credential]:
    """Build a lookup of credentials by credential_id.

    v0.1 credential IDs (AWS access key ARNs, role ARNs, prefixed GitHub
    identifiers) are unique across our supported sources, so a single-key
    index is sufficient. If a future source introduces collisions, switch
    to a (source, id) tuple key.
    """
    index: dict[str, Credential] = {}
    rows = conn.execute(
        """
        SELECT source, credential_id, credential_type, owner_source, owner_id,
               scopes, is_active, metadata
        FROM credentials
        """
    ).fetchall()
    for r in rows:
        index[r["credential_id"]] = Credential(
            source=r["source"],
            credential_id=r["credential_id"],
            credential_type=r["credential_type"],
            owner_source=r["owner_source"],
            owner_id=r["owner_id"],
            scopes=json.loads(r["scopes"]) if r["scopes"] else [],
            is_active=bool(r["is_active"]),
            metadata=json.loads(r["metadata"]) if r["metadata"] else {},
        )
    return index


def _find_credential(
    finding: Finding, index: dict[str, Credential]
) -> Credential | None:
    cred_id = (finding.evidence or {}).get("credential_id")
    if not cred_id:
        return None
    return index.get(cred_id)
