"""Local web dashboard.

A small FastAPI app that renders the same data the CLI exposes, but
interactively. Three pages:
  /            Overview (severity counts, source counts, top broad findings)
  /findings    Filterable findings list with expandable evidence
  /identities  Cross-source person view, mirrors `afterlife identities`

No DB writes, no auth, single-process. Intended for `afterlife serve` on
localhost; not hardened for multi-user or public deployment.
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from afterlife import __version__, db
from afterlife.graph.identity_graph import IdentityGraph

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
TEMPLATE_DIR = Path(__file__).parent / "templates"


def create_app(db_path: Path) -> FastAPI:
    app = FastAPI(title="Afterlife", version=__version__)
    app.state.db_path = Path(db_path).resolve()
    templates = Jinja2Templates(directory=str(TEMPLATE_DIR))

    @app.get("/", response_class=HTMLResponse)
    def overview(request: Request):
        findings = _load_findings(app.state.db_path)
        graph = IdentityGraph.from_db(app.state.db_path)
        persons = list(graph.persons())
        cross_source = [p for p in persons if p.is_cross_source]

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

        source_counts: dict[str, int] = {}
        with db.connect(app.state.db_path) as conn:
            for row in conn.execute(
                "SELECT source, COUNT(*) AS n FROM identities GROUP BY source"
            ):
                source_counts[row["source"]] = row["n"]

        # Top by descending blast radius, ties broken by severity, then rule_id.
        top = sorted(
            findings,
            key=lambda f: (
                -((f.get("blast_radius") or {}).get("score") or 0.0),
                SEVERITY_ORDER.get(f["severity"], 99),
                f["rule_id"],
            ),
        )[:5]
        for f in top:
            f["blast_label"] = _blast_label(f.get("blast_radius"))

        return templates.TemplateResponse(
            request=request,
            name="overview.html",
            context={
                "version": __version__,
                "total_findings": len(findings),
                "severity_counts": severity_counts,
                "source_counts": source_counts,
                "total_persons": len(persons),
                "cross_source_count": len(cross_source),
                "top_findings": top,
            },
        )

    @app.get("/findings", response_class=HTMLResponse)
    def findings_page(
        request: Request,
        severity: str | None = Query(None),
        rule: str | None = Query(None),
        blast: str | None = Query(None),
    ):
        findings = _load_findings(app.state.db_path)
        for f in findings:
            f["blast_label"] = _blast_label(f.get("blast_radius"))
            f["evidence_pretty"] = json.dumps(
                f.get("evidence") or {}, indent=2, sort_keys=True
            )

        if severity:
            findings = [f for f in findings if f["severity"] == severity]
        if rule:
            findings = [f for f in findings if f["rule_id"] == rule]
        if blast:
            findings = [f for f in findings if f["blast_label"] == blast]

        findings.sort(
            key=lambda f: (
                SEVERITY_ORDER.get(f["severity"], 99),
                -((f.get("blast_radius") or {}).get("score") or 0.0),
                f.get("detected_at") or "",
            )
        )

        rule_ids = sorted(
            {f["rule_id"] for f in _load_findings(app.state.db_path)}
        )

        return templates.TemplateResponse(
            request=request,
            name="findings.html",
            context={
                "version": __version__,
                "findings": findings,
                "rule_ids": rule_ids,
                "filter_severity": severity,
                "filter_rule": rule,
                "filter_blast": blast,
            },
        )

    @app.get("/identities", response_class=HTMLResponse)
    def identities_page(
        request: Request,
        cross_source_only: bool = Query(False),
    ):
        graph = IdentityGraph.from_db(app.state.db_path)
        persons = list(graph.persons())
        if cross_source_only:
            persons = [p for p in persons if p.is_cross_source]
        persons.sort(
            key=lambda p: (
                not p.is_cross_source,
                p.canonical_email or "zzz",
            )
        )

        sources = sorted({s for p in graph.persons() for s in p.sources})
        cross_source_count = sum(
            1 for p in graph.persons() if p.is_cross_source
        )

        return templates.TemplateResponse(
            request=request,
            name="identities.html",
            context={
                "version": __version__,
                "persons": persons,
                "sources": sources,
                "total_persons": len(list(graph.persons())),
                "cross_source_count": cross_source_count,
                "cross_source_only": cross_source_only,
            },
        )

    return app


def _load_findings(db_path: Path) -> list[dict]:
    with db.connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT rule_id, severity, title, description,
                   identity_source, identity_id, evidence,
                   suggested_remediation, blast_radius, detected_at
            FROM findings
            """
        ).fetchall()
    findings: list[dict] = []
    for r in rows:
        d = dict(r)
        if d.get("evidence"):
            d["evidence"] = json.loads(d["evidence"])
        if d.get("blast_radius"):
            d["blast_radius"] = json.loads(d["blast_radius"])
        findings.append(d)
    return findings


def _blast_label(blast: dict | None) -> str | None:
    if not blast:
        return None
    s = blast.get("score") or 0.0
    if s >= 0.7:
        return "broad"
    if s >= 0.4:
        return "moderate"
    return "limited"
