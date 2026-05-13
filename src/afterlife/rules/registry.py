import importlib
import pkgutil
from pathlib import Path

from afterlife import db
from afterlife.config import DEFAULT, Config
from afterlife.graph.identity_graph import IdentityGraph
from afterlife.models import Finding, Severity
from afterlife.rules.base import Rule

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


def run_all(db_path: Path, config: Config = DEFAULT) -> list[Finding]:
    all_rules()
    findings: list[Finding] = []
    with db.connect(db_path) as conn:
        graph = IdentityGraph.from_conn(conn)
        for r in _RULES:
            for f in r.evaluate(conn, config, graph):
                db.insert_finding(conn, f)
                findings.append(f)
    return findings
