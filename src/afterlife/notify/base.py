"""Notification primitives shared by every channel.

A notifier turns an `Alert` (the batch of newly-appearing findings from an
analyze run) into a message on some channel. Channels are intentionally thin:
formatting lives here so every channel says the same thing.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from afterlife.models import Finding, Severity

SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


def meets_threshold(severity: Severity, minimum: Severity) -> bool:
    """True if `severity` is at least as severe as `minimum`."""
    return SEVERITY_RANK[severity] <= SEVERITY_RANK[minimum]


@dataclass
class Alert:
    """A batch of findings worth notifying about (new and/or reopened)."""

    findings: list[Finding] = field(default_factory=list)
    new_count: int = 0
    reopened_count: int = 0

    def __bool__(self) -> bool:
        return bool(self.findings)

    @property
    def counts_by_severity(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity.value] = out.get(f.severity.value, 0) + 1
        return out

    def title(self) -> str:
        parts = []
        if self.new_count:
            parts.append(f"{self.new_count} new")
        if self.reopened_count:
            parts.append(f"{self.reopened_count} reopened")
        change = " and ".join(parts) or f"{len(self.findings)}"
        noun = "finding" if len(self.findings) == 1 else "findings"
        return f"Afterlife: {change} {noun} need attention"

    def ordered_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: SEVERITY_RANK[f.severity])

    def lines(self) -> list[str]:
        """One human-readable line per finding, most severe first."""
        return [
            f"[{f.severity.value.upper()}] {f.title} ({f.rule_id})"
            for f in self.ordered_findings()
        ]


class Notifier(ABC):
    """A channel that can deliver an Alert."""

    name: str

    @abstractmethod
    def send(self, alert: Alert) -> None:
        """Deliver the alert. Raise on failure so the dispatcher can record it."""
