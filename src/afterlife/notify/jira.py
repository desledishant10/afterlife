"""Jira notifier (Pro): file a remediation issue for new findings.

Creates one Jira issue summarizing the new and reopened findings from an
analyze run, so ghost access becomes tracked, assignable work instead of a
line in a report. Uses the Jira Cloud REST API v3 with an email + API-token
basic auth; the description is sent as Atlassian Document Format (ADF).

This is a Pro feature: it is only wired into the dispatch when the license
grants FEATURE_INTEGRATIONS (see afterlife.notify.NotifyConfig.build_notifiers).
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from afterlife.notify.base import Alert, Notifier

_MAX_LINES = 25


@dataclass
class JiraSettings:
    base_url: str      # https://your-org.atlassian.net
    email: str
    api_token: str
    project_key: str   # e.g. "SEC"
    issue_type: str = "Task"


def _adf(lines: list[str]) -> dict:
    """Minimal Atlassian Document Format: one paragraph per line."""
    content = [
        {"type": "paragraph", "content": [{"type": "text", "text": line}]}
        for line in (lines or ["(no details)"])
    ]
    return {"type": "doc", "version": 1, "content": content}


class JiraNotifier(Notifier):
    name = "jira"

    def __init__(self, settings: JiraSettings, *, timeout: float = 15.0):
        self.settings = settings
        self.timeout = timeout

    def _payload(self, alert: Alert) -> dict:
        lines = alert.lines()
        shown = lines[:_MAX_LINES]
        if len(lines) > _MAX_LINES:
            shown.append(f"...and {len(lines) - _MAX_LINES} more.")
        body = [
            "Afterlife detected credentials that need attention. "
            "Each line is one finding, most severe first.",
            *shown,
            "Investigate and revoke or remediate as appropriate. "
            "Afterlife only reports; it does not change anything.",
        ]
        return {
            "fields": {
                "project": {"key": self.settings.project_key},
                "summary": alert.title(),
                "description": _adf(body),
                "issuetype": {"name": self.settings.issue_type},
            }
        }

    def send(self, alert: Alert) -> None:
        s = self.settings
        url = s.base_url.rstrip("/") + "/rest/api/3/issue"
        response = httpx.post(
            url,
            json=self._payload(alert),
            auth=(s.email, s.api_token),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            timeout=self.timeout,
        )
        response.raise_for_status()
