from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


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
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
