"""Allowlist / suppression support.

Findings can be suppressed by a YAML file that names credentials, rules, or
identities to skip. Suppressed findings are still produced and stored (so they
remain auditable), but they're flagged so reports and the dashboard can hide
them by default.

YAML shape (top-level list, each entry is a suppression rule):

  - rule_id: NEVER-USED
    credential_id: AKIA-BREAKGLASS
    reason: Break-glass admin key, intentionally dormant
    until: 2026-12-31

  - credential_id: arn:aws:iam::123:role/SeasonalReportingRole
    reason: Used once a year for tax reporting

  - identity_source: google
    identity_id: 100000000000000000005
    reason: Nina is a new hire, AWS provisioning pending

A finding matches a suppression if every named field on the suppression matches
the finding. An empty suppression (no fields) would match everything; the
loader treats that as a config error and skips it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Iterable

import yaml

from afterlife.models import Finding


@dataclass
class Suppression:
    rule_id: str | None = None
    credential_id: str | None = None
    identity_source: str | None = None
    identity_id: str | None = None
    reason: str = ""
    until: date | None = None

    @property
    def is_specific(self) -> bool:
        return any(
            (self.rule_id, self.credential_id, self.identity_source, self.identity_id)
        )

    def is_active(self, today: date) -> bool:
        return self.until is None or today <= self.until

    def matches(self, finding: Finding) -> bool:
        if self.rule_id and finding.rule_id != self.rule_id:
            return False
        if self.credential_id:
            cred_id = (finding.evidence or {}).get("credential_id")
            if cred_id != self.credential_id:
                return False
        if self.identity_source and finding.identity_source != self.identity_source:
            return False
        if self.identity_id and finding.identity_id != self.identity_id:
            return False
        return True


def load_allowlist(path: Path | None) -> list[Suppression]:
    if path is None:
        return []
    p = Path(path)
    if not p.exists():
        return []
    raw = yaml.safe_load(p.read_text()) or []
    if isinstance(raw, dict):
        raw = raw.get("suppressions", [])
    if not isinstance(raw, list):
        raise ValueError(
            f"{p}: top-level must be a list of suppressions (or a "
            "'suppressions:' mapping containing one)"
        )
    out: list[Suppression] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"{p}: entry {i} is not a mapping")
        until = item.get("until")
        if isinstance(until, str):
            until = date.fromisoformat(until)
        elif isinstance(until, datetime):
            until = until.date()
        supp = Suppression(
            rule_id=item.get("rule_id"),
            credential_id=item.get("credential_id"),
            identity_source=item.get("identity_source"),
            identity_id=item.get("identity_id"),
            reason=item.get("reason") or "",
            until=until,
        )
        if not supp.is_specific:
            # Refuse to load a catch-all suppression that would silence everything.
            continue
        out.append(supp)
    return out


def apply_suppressions(
    findings: Iterable[Finding],
    suppressions: Iterable[Suppression],
    today: date | None = None,
) -> None:
    today = today or datetime.utcnow().date()
    active = [s for s in suppressions if s.is_active(today)]
    for f in findings:
        for s in active:
            if s.matches(f):
                f.suppressed = True
                f.suppression_reason = s.reason or "suppressed by allowlist"
                break
