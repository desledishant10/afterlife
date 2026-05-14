"""Local web dashboard.

A small FastAPI app that renders the same data the CLI exposes, but
interactively. Pages:
  /                                Overview with severity tiles, identity stats,
                                   top findings, and a sources chart.
  /findings                        Filterable findings list with expandable evidence.
  /findings/{id}                   Finding detail with linked person and credential.
  /credentials                     Credentials list with filters.
  /credentials/{source}/{id:path}  Credential detail with owner and related findings.
  /identities                      Cross-source person view.
  /persons/{source}/{id:path}      Person detail with linked identities + creds + findings.

No DB writes, no auth, single-process. Intended for `afterlife serve` on
localhost; not hardened for multi-user or public deployment.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from afterlife import __version__, db
from afterlife.graph.identity_graph import IdentityGraph, Person
from afterlife.web.middleware import SecurityHeadersMiddleware

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
TEMPLATE_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"


def create_app(db_path: Path) -> FastAPI:
    app = FastAPI(
        title="Afterlife",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.db_path = Path(db_path).resolve()
    app.add_middleware(SecurityHeadersMiddleware)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    templates = Jinja2Templates(directory=str(TEMPLATE_DIR))

    @app.get("/", response_class=HTMLResponse)
    def overview(request: Request):
        findings = _load_findings(app.state.db_path)
        graph = IdentityGraph.from_db(app.state.db_path)
        persons = list(graph.persons())
        cross_source = [p for p in persons if p.is_cross_source]

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        blast_counts = {"broad": 0, "moderate": 0, "limited": 0}
        for f in findings:
            severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1
            label = _blast_label(f.get("blast_radius"))
            if label:
                blast_counts[label] = blast_counts.get(label, 0) + 1

        source_counts: dict[str, int] = {}
        credential_count = 0
        with db.connect(app.state.db_path) as conn:
            for row in conn.execute(
                "SELECT source, COUNT(*) AS n FROM identities GROUP BY source"
            ):
                source_counts[row["source"]] = row["n"]
            credential_count = conn.execute(
                "SELECT COUNT(*) AS n FROM credentials"
            ).fetchone()["n"]

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
                "blast_counts": blast_counts,
                "source_counts": source_counts,
                "credential_count": credential_count,
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
        q: str | None = Query(None),
        show_suppressed: bool = Query(False),
    ):
        all_findings = _load_findings(app.state.db_path)
        findings = list(all_findings)
        for f in findings:
            f["blast_label"] = _blast_label(f.get("blast_radius"))
            f["evidence_pretty"] = json.dumps(
                f.get("evidence") or {}, indent=2, sort_keys=True
            )

        if not show_suppressed:
            findings = [f for f in findings if not f.get("suppressed")]
        if severity:
            findings = [f for f in findings if f["severity"] == severity]
        if rule:
            findings = [f for f in findings if f["rule_id"] == rule]
        if blast:
            findings = [f for f in findings if f["blast_label"] == blast]
        if q:
            needle = q.lower().strip()
            findings = [f for f in findings if _matches_query(f, needle)]

        findings.sort(
            key=lambda f: (
                f.get("suppressed", False),
                SEVERITY_ORDER.get(f["severity"], 99),
                -((f.get("blast_radius") or {}).get("score") or 0.0),
                f.get("detected_at") or "",
            )
        )

        rule_ids = sorted({f["rule_id"] for f in all_findings})
        suppressed_count = sum(1 for f in all_findings if f.get("suppressed"))

        is_partial = request.headers.get("HX-Request") == "true"
        template = "_findings_list.html" if is_partial else "findings.html"

        return templates.TemplateResponse(
            request=request,
            name=template,
            context={
                "version": __version__,
                "findings": findings,
                "total_findings": len(all_findings),
                "rule_ids": rule_ids,
                "filter_severity": severity,
                "filter_rule": rule,
                "filter_blast": blast,
                "query": q or "",
                "show_suppressed": show_suppressed,
                "suppressed_count": suppressed_count,
            },
        )

    @app.get("/findings/{finding_id}", response_class=HTMLResponse)
    def finding_detail(request: Request, finding_id: int):
        finding = _load_finding(app.state.db_path, finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        finding["blast_label"] = _blast_label(finding.get("blast_radius"))
        finding["evidence_pretty"] = json.dumps(
            finding.get("evidence") or {}, indent=2, sort_keys=True
        )

        # Linked person (if the finding identifies an identity)
        person: Person | None = None
        if finding.get("identity_source") and finding.get("identity_id"):
            graph = IdentityGraph.from_db(app.state.db_path)
            person = graph.person_for(
                finding["identity_source"], finding["identity_id"]
            )

        # Linked credential (if evidence includes credential_id)
        credential = None
        evidence = finding.get("evidence") or {}
        cred_id = evidence.get("credential_id")
        if cred_id:
            credential = _load_credential_by_id(app.state.db_path, cred_id)

        return templates.TemplateResponse(
            request=request,
            name="finding_detail.html",
            context={
                "version": __version__,
                "finding": finding,
                "person": person,
                "credential": credential,
            },
        )

    @app.get("/credentials", response_class=HTMLResponse)
    def credentials_page(
        request: Request,
        source: str | None = Query(None),
        cred_type: str | None = Query(None, alias="type"),
        active: str | None = Query(None),
        q: str | None = Query(None),
    ):
        creds = _load_credentials(app.state.db_path)
        all_creds = list(creds)

        if source:
            creds = [c for c in creds if c["source"] == source]
        if cred_type:
            creds = [c for c in creds if c["credential_type"] == cred_type]
        if active == "yes":
            creds = [c for c in creds if c["is_active"]]
        elif active == "no":
            creds = [c for c in creds if not c["is_active"]]
        if q:
            needle = q.lower().strip()
            creds = [
                c for c in creds
                if needle in (c["credential_id"] or "").lower()
                or needle in (c["credential_type"] or "").lower()
                or any(needle in (s or "").lower() for s in c.get("scopes") or [])
            ]

        creds.sort(key=lambda c: (c["source"], c["credential_type"], c["credential_id"]))

        sources = sorted({c["source"] for c in all_creds})
        types = sorted({c["credential_type"] for c in all_creds})

        is_partial = request.headers.get("HX-Request") == "true"
        template = "_credentials_list.html" if is_partial else "credentials.html"

        return templates.TemplateResponse(
            request=request,
            name=template,
            context={
                "version": __version__,
                "credentials": creds,
                "total_credentials": len(all_creds),
                "sources": sources,
                "types": types,
                "filter_source": source,
                "filter_type": cred_type,
                "filter_active": active,
                "query": q or "",
            },
        )

    @app.get(
        "/credentials/{source}/{credential_id:path}",
        response_class=HTMLResponse,
    )
    def credential_detail(request: Request, source: str, credential_id: str):
        cred = _load_credential(app.state.db_path, source, credential_id)
        if cred is None:
            raise HTTPException(status_code=404, detail="Credential not found")

        # Owner person (if any)
        owner_person: Person | None = None
        if cred.get("owner_source") and cred.get("owner_id"):
            graph = IdentityGraph.from_db(app.state.db_path)
            owner_person = graph.person_for(
                cred["owner_source"], cred["owner_id"]
            )

        # Findings whose evidence.credential_id matches this credential
        findings = [
            f for f in _load_findings(app.state.db_path)
            if (f.get("evidence") or {}).get("credential_id") == credential_id
        ]
        for f in findings:
            f["blast_label"] = _blast_label(f.get("blast_radius"))
        findings.sort(
            key=lambda f: (
                SEVERITY_ORDER.get(f["severity"], 99),
                -((f.get("blast_radius") or {}).get("score") or 0.0),
            )
        )

        return templates.TemplateResponse(
            request=request,
            name="credential_detail.html",
            context={
                "version": __version__,
                "credential": cred,
                "owner_person": owner_person,
                "findings": findings,
            },
        )

    @app.get("/identities", response_class=HTMLResponse)
    def identities_page(
        request: Request,
        cross_source_only: bool = Query(False),
        q: str | None = Query(None),
    ):
        graph = IdentityGraph.from_db(app.state.db_path)
        persons = list(graph.persons())
        all_count = len(persons)
        if cross_source_only:
            persons = [p for p in persons if p.is_cross_source]
        if q:
            needle = q.lower().strip()
            persons = [p for p in persons if _person_matches(p, needle)]
        persons.sort(
            key=lambda p: (not p.is_cross_source, p.canonical_email or "zzz")
        )

        sources = sorted({s for p in graph.persons() for s in p.sources})
        cross_source_count = sum(1 for p in graph.persons() if p.is_cross_source)

        is_partial = request.headers.get("HX-Request") == "true"
        template = "_identities_list.html" if is_partial else "identities.html"

        return templates.TemplateResponse(
            request=request,
            name=template,
            context={
                "version": __version__,
                "persons": persons,
                "sources": sources,
                "total_persons": all_count,
                "cross_source_count": cross_source_count,
                "cross_source_only": cross_source_only,
                "query": q or "",
            },
        )

    @app.get(
        "/persons/{source}/{source_id:path}",
        response_class=HTMLResponse,
    )
    def person_detail(request: Request, source: str, source_id: str):
        graph = IdentityGraph.from_db(app.state.db_path)
        person = graph.person_for(source, source_id)
        if person is None:
            raise HTTPException(status_code=404, detail="Person not found")

        owned_credentials = graph.credentials_for_person(person)
        # Re-hydrate via the DB so we get scopes / status / etc. uniformly.
        owned_ids = {c.credential_id for c in owned_credentials}
        full_credentials = [
            c for c in _load_credentials(app.state.db_path)
            if c["credential_id"] in owned_ids
        ]

        person_identity_keys = {
            (i.source, i.source_id) for i in person.identities
        }
        all_findings = _load_findings(app.state.db_path)
        person_findings: list[dict[str, Any]] = []
        for f in all_findings:
            ident_key = (f.get("identity_source"), f.get("identity_id"))
            cred_id = (f.get("evidence") or {}).get("credential_id")
            if ident_key in person_identity_keys or cred_id in owned_ids:
                f["blast_label"] = _blast_label(f.get("blast_radius"))
                person_findings.append(f)
        person_findings.sort(
            key=lambda f: (
                SEVERITY_ORDER.get(f["severity"], 99),
                -((f.get("blast_radius") or {}).get("score") or 0.0),
            )
        )

        return templates.TemplateResponse(
            request=request,
            name="person_detail.html",
            context={
                "version": __version__,
                "person": person,
                "credentials": full_credentials,
                "findings": person_findings,
            },
        )

    return app


def _load_findings(db_path: Path) -> list[dict[str, Any]]:
    with db.connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT id, rule_id, severity, title, description,
                   identity_source, identity_id, evidence,
                   suggested_remediation, blast_radius,
                   suppressed, suppression_reason, detected_at
            FROM findings
            """
        ).fetchall()
    findings: list[dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        if d.get("evidence"):
            d["evidence"] = json.loads(d["evidence"])
        if d.get("blast_radius"):
            d["blast_radius"] = json.loads(d["blast_radius"])
        d["suppressed"] = bool(d.get("suppressed"))
        findings.append(d)
    return findings


def _load_finding(db_path: Path, finding_id: int) -> dict[str, Any] | None:
    with db.connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT id, rule_id, severity, title, description,
                   identity_source, identity_id, evidence,
                   suggested_remediation, blast_radius,
                   suppressed, suppression_reason, detected_at
            FROM findings WHERE id = ?
            """,
            (finding_id,),
        ).fetchone()
    if row is None:
        return None
    d = dict(row)
    if d.get("evidence"):
        d["evidence"] = json.loads(d["evidence"])
    if d.get("blast_radius"):
        d["blast_radius"] = json.loads(d["blast_radius"])
    d["suppressed"] = bool(d.get("suppressed"))
    return d


def _load_credentials(db_path: Path) -> list[dict[str, Any]]:
    with db.connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT source, credential_id, credential_type, owner_source, owner_id,
                   created_at, last_used_at, scopes, is_active, metadata
            FROM credentials
            """
        ).fetchall()
    return [_credential_row_to_dict(r) for r in rows]


def _load_credential(
    db_path: Path, source: str, credential_id: str
) -> dict[str, Any] | None:
    with db.connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT source, credential_id, credential_type, owner_source, owner_id,
                   created_at, last_used_at, scopes, is_active, metadata
            FROM credentials
            WHERE source = ? AND credential_id = ?
            """,
            (source, credential_id),
        ).fetchone()
    return _credential_row_to_dict(row) if row else None


def _load_credential_by_id(
    db_path: Path, credential_id: str
) -> dict[str, Any] | None:
    with db.connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT source, credential_id, credential_type, owner_source, owner_id,
                   created_at, last_used_at, scopes, is_active, metadata
            FROM credentials
            WHERE credential_id = ?
            LIMIT 1
            """,
            (credential_id,),
        ).fetchone()
    return _credential_row_to_dict(row) if row else None


def _credential_row_to_dict(row: sqlite3.Row | None) -> dict[str, Any]:
    if row is None:
        return {}
    d = dict(row)
    d["is_active"] = bool(d.get("is_active"))
    if d.get("scopes"):
        d["scopes"] = json.loads(d["scopes"])
    else:
        d["scopes"] = []
    if d.get("metadata"):
        d["metadata"] = json.loads(d["metadata"])
    else:
        d["metadata"] = {}
    return d


def _matches_query(finding: dict[str, Any], needle: str) -> bool:
    haystack = " ".join(
        str(x) for x in (
            finding.get("title") or "",
            finding.get("description") or "",
            finding.get("rule_id") or "",
            finding.get("identity_id") or "",
            (finding.get("evidence") or {}).get("credential_id", ""),
            (finding.get("evidence") or {}).get("owner_email", ""),
        )
    ).lower()
    return needle in haystack


def _person_matches(person: Person, needle: str) -> bool:
    if person.canonical_email and needle in person.canonical_email.lower():
        return True
    for ident in person.identities:
        if needle in (ident.source_id or "").lower():
            return True
        if ident.name and needle in ident.name.lower():
            return True
        if ident.email and needle in ident.email.lower():
            return True
    return False


def _blast_label(blast: dict | None) -> str | None:
    if not blast:
        return None
    s = blast.get("score") or 0.0
    if s >= 0.7:
        return "broad"
    if s >= 0.4:
        return "moderate"
    return "limited"
