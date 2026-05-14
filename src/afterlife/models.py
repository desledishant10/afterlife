from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
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
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
