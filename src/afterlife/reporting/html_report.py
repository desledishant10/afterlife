"""Single-file HTML audit report.

Renders the findings table and identity graph into a self-contained HTML
document. No external CSS, no JavaScript dependencies, safe to attach to
an email or commit to a private repo.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Template

from afterlife import __version__, db
from afterlife.graph.identity_graph import IdentityGraph

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Afterlife report ({{ generated_at[:10] }})</title>
<style>
  :root {
    --bg: #fafafa;
    --fg: #1a1a1a;
    --muted: #6a6a6a;
    --border: #e0e0e0;
    --critical: #b71c1c;
    --high: #ad1457;
    --medium: #e65100;
    --low: #1565c0;
    --link: #2e7d32;
    --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  * { box-sizing: border-box; }
  body {
    background: var(--bg);
    color: var(--fg);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
    max-width: 1000px;
    margin: 2rem auto;
    padding: 0 1.5rem 4rem;
    line-height: 1.5;
  }
  h1 { margin-bottom: 0.25rem; font-size: 1.75rem; }
  .meta { color: var(--muted); font-size: 0.875rem; margin-bottom: 2rem; }
  .summary {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 0.75rem;
    margin-bottom: 2rem;
  }
  .metric {
    background: white;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 1rem;
    text-align: center;
  }
  .metric .count { font-size: 2rem; font-weight: 600; display: block; line-height: 1; }
  .metric.critical .count { color: var(--critical); }
  .metric.high .count { color: var(--high); }
  .metric.medium .count { color: var(--medium); }
  .metric.low .count { color: var(--low); }
  .metric .label {
    color: var(--muted);
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-top: 0.5rem;
    display: block;
  }
  h2 {
    margin-top: 3rem;
    margin-bottom: 1rem;
    border-bottom: 2px solid var(--border);
    padding-bottom: 0.5rem;
    font-size: 1.25rem;
  }
  details.finding {
    background: white;
    border: 1px solid var(--border);
    border-left: 4px solid var(--border);
    border-radius: 4px;
    padding: 0.75rem 1rem;
    margin-bottom: 0.5rem;
  }
  details.finding.critical { border-left-color: var(--critical); }
  details.finding.high { border-left-color: var(--high); }
  details.finding.medium { border-left-color: var(--medium); }
  details.finding.low { border-left-color: var(--low); }
  details.finding summary {
    cursor: pointer;
    font-weight: 500;
    list-style: none;
  }
  details.finding summary::-webkit-details-marker { display: none; }
  details.finding summary::before {
    content: "▸";
    color: var(--muted);
    margin-right: 0.5rem;
    display: inline-block;
    transition: transform 0.1s;
  }
  details.finding[open] summary::before { transform: rotate(90deg); }
  .badge {
    display: inline-block;
    padding: 0.125rem 0.5rem;
    border-radius: 3px;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-weight: 600;
    margin-right: 0.5rem;
    color: white;
    vertical-align: 2px;
  }
  .badge.critical { background: var(--critical); }
  .badge.high { background: var(--high); }
  .badge.medium { background: var(--medium); }
  .badge.low { background: var(--low); }
  .rule-id {
    font-family: var(--mono);
    color: var(--muted);
    font-size: 0.8rem;
    margin-left: 0.5rem;
  }
  details.finding .body {
    margin-top: 0.75rem;
    padding-top: 0.75rem;
    border-top: 1px solid var(--border);
  }
  h4 {
    margin-top: 1rem;
    margin-bottom: 0.25rem;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
  }
  pre {
    background: #f5f5f5;
    padding: 0.75rem;
    border-radius: 4px;
    font-family: var(--mono);
    font-size: 0.8rem;
    overflow-x: auto;
    margin: 0;
  }
  .person {
    background: white;
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.75rem 1rem;
    margin-bottom: 0.5rem;
  }
  .person.cross-source { border-left: 4px solid var(--link); }
  .person-header { font-weight: 500; }
  .person-tag {
    color: var(--link);
    font-size: 0.75rem;
    margin-left: 0.5rem;
    font-weight: normal;
  }
  .identity-row {
    font-family: var(--mono);
    font-size: 0.825rem;
    color: var(--muted);
    margin-top: 0.25rem;
  }
  .identity-row .src {
    display: inline-block;
    min-width: 4.5rem;
    color: var(--fg);
  }
  .identity-row .status-suspended,
  .identity-row .status-archived,
  .identity-row .status-deprovisioned { color: var(--critical); }
  .footer {
    color: var(--muted);
    font-size: 0.75rem;
    margin-top: 4rem;
    text-align: center;
  }
  .empty {
    color: var(--muted);
    font-style: italic;
    padding: 1rem;
    background: white;
    border: 1px dashed var(--border);
    border-radius: 4px;
    text-align: center;
  }
</style>
</head>
<body>

<h1>Afterlife report</h1>
<p class="meta">Generated {{ generated_at }} &middot; Afterlife v{{ version }}</p>

<div class="summary">
  <div class="metric critical"><span class="count">{{ counts.critical }}</span><span class="label">Critical</span></div>
  <div class="metric high"><span class="count">{{ counts.high }}</span><span class="label">High</span></div>
  <div class="metric medium"><span class="count">{{ counts.medium }}</span><span class="label">Medium</span></div>
  <div class="metric low"><span class="count">{{ counts.low }}</span><span class="label">Low</span></div>
</div>

<h2>Findings ({{ total }})</h2>
{% if findings %}
  {% for f in findings %}
  <details class="finding {{ f.severity }}">
    <summary>
      <span class="badge {{ f.severity }}">{{ f.severity }}</span>{{ f.title }}<span class="rule-id">{{ f.rule_id }}</span>
    </summary>
    <div class="body">
      <p>{{ f.description }}</p>
      <h4>Evidence</h4>
      <pre>{{ f.evidence_pretty }}</pre>
      {% if f.suggested_remediation %}
      <h4>Suggested remediation</h4>
      <p>{{ f.suggested_remediation }}</p>
      {% endif %}
    </div>
  </details>
  {% endfor %}
{% else %}
  <div class="empty">No findings recorded.</div>
{% endif %}

<h2>Identity graph ({{ persons|length }} persons, {{ cross_source_count }} cross-source)</h2>
{% if persons %}
  {% for person in persons %}
  <div class="person{% if person.is_cross_source %} cross-source{% endif %}">
    <div class="person-header">
      {% if person.canonical_email %}{{ person.canonical_email }}{% else %}(no email){% endif %}
      {% if person.is_cross_source %}<span class="person-tag">cross-source</span>{% endif %}
    </div>
    {% for identity in person.identities %}
    <div class="identity-row">
      <span class="src">{{ identity.source }}</span>
      {{ identity.source_id }}
      <span class="status-{{ identity.status }}">({{ identity.status }})</span>
    </div>
    {% endfor %}
  </div>
  {% endfor %}
{% else %}
  <div class="empty">No identities collected yet.</div>
{% endif %}

<p class="footer">Generated by <code>afterlife report --format html</code>.</p>

</body>
</html>
"""


def write_html_report(db_path: Path) -> str:
    findings = _load_findings(db_path)
    findings.sort(
        key=lambda f: (SEVERITY_ORDER.get(f["severity"], 99), f.get("detected_at") or "")
    )
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        f["evidence_pretty"] = json.dumps(
            f.get("evidence") or {}, indent=2, sort_keys=True
        )

    graph = IdentityGraph.from_db(db_path)
    persons = sorted(
        graph.persons(),
        key=lambda p: (not p.is_cross_source, p.canonical_email or "zzz"),
    )
    cross_source_count = sum(1 for p in persons if p.is_cross_source)

    template = Template(HTML_TEMPLATE, autoescape=True)
    return template.render(
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        version=__version__,
        findings=findings,
        counts=counts,
        total=len(findings),
        persons=persons,
        cross_source_count=cross_source_count,
    )


def _load_findings(db_path: Path) -> list[dict[str, Any]]:
    with db.connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT rule_id, severity, title, description,
                   identity_source, identity_id, evidence,
                   suggested_remediation, detected_at
            FROM findings
            """
        ).fetchall()
    findings: list[dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        if d.get("evidence"):
            d["evidence"] = json.loads(d["evidence"])
        findings.append(d)
    return findings
