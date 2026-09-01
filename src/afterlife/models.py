import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(slots=True)
class BlastRadius:
    """Per-credential estimate of what an attacker could do if it leaked.

    `score` is in [0.0, 1.0]. `factors` are human-readable strings explaining
    how the score was derived (intended for display in reports).
    """

    score: float
    factors: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        if self.score >= 0.7:
            return "broad"
        if self.score >= 0.4:
            return "moderate"
        return "limited"


@dataclass(slots=True)
class Identity:
    source: str
    source_id: str
    email: str | None
    name: str | None
    status: str
    last_seen: datetime | None = None
    metadata: dict = field(default_factory=dict)


@dataclass(slots=True)
class Credential:
    source: str
    credential_id: str
    credential_type: str
    owner_source: str | None = None
    owner_id: str | None = None
    created_at: datetime | None = None
    last_used_at: datetime | None = None
    scopes: list[str] = field(default_factory=list)
    is_active: bool = True
    metadata: dict = field(default_factory=dict)


@dataclass(slots=True)
class Finding:
    rule_id: str
    severity: Severity
    title: str
    description: str
    identity_source: str | None = None
    identity_id: str | None = None
    evidence: dict = field(default_factory=dict)
    suggested_remediation: str = ""
    blast_radius: BlastRadius | None = None
    suppressed: bool = False
    suppression_reason: str | None = None
    detected_at: datetime = field(default_factory=lambda: datetime.now(UTC))


def finding_fingerprint(f: Finding) -> str:
    """Stable identity for a finding across scans.

    A finding is (rule, subject). The subject is the thing the finding is
    about, chosen from the most stable identifier available:

    1. `evidence["credential_id"]` for credential-targeting rules
       (OFFBOARDED-OWNER, CROSS-ACCOUNT-TRUST, UNROTATED-KEY, ...), and
    2. `(identity_source, identity_id)` for identity-targeting rules
       (ADMIN-CONCENTRATION, ORPHANED-IDENTITY, ADMIN-WITHOUT-MFA, ...).

    The fallback (evidence + title) only applies to synthetic findings that
    carry neither; every shipped rule uses one of the two stable paths, so a
    finding keeps the same fingerprint run to run and can be tracked as it
    appears, persists, and resolves.
    """
    evidence = f.evidence or {}
    credential_id = evidence.get("credential_id")
    if credential_id:
        subject = f"cred:{credential_id}"
    elif f.identity_source and f.identity_id:
        subject = f"id:{f.identity_source}:{f.identity_id}"
    else:
        subject = "evi:" + json.dumps(evidence, sort_keys=True, default=str)
        subject += f"|{f.title}"
    raw = f"{f.rule_id}|{subject}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
