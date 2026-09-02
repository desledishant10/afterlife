"""Alerting: turn the new/reopened findings from an analyze run into messages.

Configuration (channels + threshold) comes from the environment or explicit
overrides and is never persisted; webhook URLs and SMTP passwords live only in
the process. The dispatch selects new/reopened findings at or above a severity
threshold, skips suppressed ones, and fans out to every configured channel.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from afterlife.db import ReconcileSummary
from afterlife.licensing import FEATURE_INTEGRATIONS, has_feature
from afterlife.models import Finding, Severity, finding_fingerprint
from afterlife.notify.base import (
    SEVERITY_RANK,
    Alert,
    Notifier,
    meets_threshold,
)
from afterlife.notify.email import EmailNotifier, SMTPSettings
from afterlife.notify.jira import JiraNotifier, JiraSettings
from afterlife.notify.slack import SlackNotifier
from afterlife.notify.webhook import WebhookNotifier

__all__ = [
    "Alert",
    "Notifier",
    "NotifyConfig",
    "SMTPSettings",
    "SlackNotifier",
    "WebhookNotifier",
    "EmailNotifier",
    "JiraNotifier",
    "JiraSettings",
    "SEVERITY_RANK",
    "meets_threshold",
    "select_alertable",
    "notify_findings",
]


def _parse_severity(value: str | None, default: Severity = Severity.HIGH) -> Severity:
    if not value:
        return default
    try:
        return Severity(value.strip().lower())
    except ValueError:
        return default


@dataclass
class NotifyConfig:
    slack_webhook: str | None = None
    webhook_url: str | None = None
    smtp: SMTPSettings | None = None
    jira: JiraSettings | None = None
    min_severity: Severity = Severity.HIGH

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> NotifyConfig:
        env = environ if environ is not None else dict(os.environ)
        smtp = None
        host = env.get("AFTERLIFE_SMTP_HOST")
        recipients = [
            r.strip() for r in env.get("AFTERLIFE_EMAIL_TO", "").split(",") if r.strip()
        ]
        if host and recipients:
            smtp = SMTPSettings(
                host=host,
                port=int(env.get("AFTERLIFE_SMTP_PORT", "587")),
                username=env.get("AFTERLIFE_SMTP_USERNAME"),
                password=env.get("AFTERLIFE_SMTP_PASSWORD"),
                use_tls=env.get("AFTERLIFE_SMTP_TLS", "true").lower() != "false",
                sender=env.get("AFTERLIFE_EMAIL_FROM", "afterlife@localhost"),
                recipients=recipients,
            )
        jira = None
        if all(
            env.get(k)
            for k in (
                "AFTERLIFE_JIRA_URL", "AFTERLIFE_JIRA_EMAIL",
                "AFTERLIFE_JIRA_TOKEN", "AFTERLIFE_JIRA_PROJECT",
            )
        ):
            jira = JiraSettings(
                base_url=env["AFTERLIFE_JIRA_URL"],
                email=env["AFTERLIFE_JIRA_EMAIL"],
                api_token=env["AFTERLIFE_JIRA_TOKEN"],
                project_key=env["AFTERLIFE_JIRA_PROJECT"],
                issue_type=env.get("AFTERLIFE_JIRA_ISSUE_TYPE", "Task"),
            )
        return cls(
            slack_webhook=env.get("AFTERLIFE_SLACK_WEBHOOK") or None,
            webhook_url=env.get("AFTERLIFE_WEBHOOK_URL") or None,
            smtp=smtp,
            jira=jira,
            min_severity=_parse_severity(env.get("AFTERLIFE_NOTIFY_MIN_SEVERITY")),
        )

    def build_notifiers(self, env: dict[str, str] | None = None) -> list[Notifier]:
        notifiers: list[Notifier] = []
        if self.slack_webhook:
            notifiers.append(SlackNotifier(self.slack_webhook))
        if self.webhook_url:
            notifiers.append(WebhookNotifier(self.webhook_url))
        if self.smtp:
            notifiers.append(EmailNotifier(self.smtp))
        # Ticketing integrations are a Pro feature.
        if self.jira and has_feature(FEATURE_INTEGRATIONS, env):
            notifiers.append(JiraNotifier(self.jira))
        return notifiers

    def unlicensed_pro_channels(self, env: dict[str, str] | None = None) -> list[str]:
        """Configured channels that are gated behind a Pro license the user lacks."""
        out: list[str] = []
        if self.jira and not has_feature(FEATURE_INTEGRATIONS, env):
            out.append("jira")
        return out

    def has_channels(self) -> bool:
        return bool(self.slack_webhook or self.webhook_url or self.smtp or self.jira)


def select_alertable(
    findings: list[Finding],
    summary: ReconcileSummary,
    min_severity: Severity = Severity.HIGH,
) -> Alert:
    """Pick the new/reopened, non-suppressed findings at/above the threshold."""
    changed = summary.changed_fingerprints
    new_fps = summary.new_fingerprints
    reopened_fps = summary.reopened_fingerprints

    alertable: list[Finding] = []
    new_count = reopened_count = 0
    for f in findings:
        if f.suppressed:
            continue
        fp = finding_fingerprint(f)
        if fp not in changed:
            continue
        if not meets_threshold(f.severity, min_severity):
            continue
        alertable.append(f)
        if fp in new_fps:
            new_count += 1
        elif fp in reopened_fps:
            reopened_count += 1
    return Alert(
        findings=alertable, new_count=new_count, reopened_count=reopened_count
    )


def notify_findings(
    findings: list[Finding],
    summary: ReconcileSummary,
    config: NotifyConfig,
) -> dict[str, str]:
    """Dispatch an alert to every configured channel.

    Returns a `{channel_name: status}` map, where status is "sent" or an error
    string. A channel failure never raises; it is reported and the other
    channels still run. Returns an empty map when there is nothing to alert on.
    """
    alert = select_alertable(findings, summary, config.min_severity)
    if not alert:
        return {}
    results: dict[str, str] = {}
    for notifier in config.build_notifiers():
        try:
            notifier.send(alert)
            results[notifier.name] = "sent"
        except Exception as exc:
            # Report the failure but never abort the other channels.
            results[notifier.name] = f"error: {exc}"
    # Surface channels the user configured but is not licensed for, so a
    # configured-but-silent Pro channel is never mistaken for a delivery.
    for channel in config.unlicensed_pro_channels():
        results[channel] = "skipped: requires a Pro license (run `afterlife license`)"
    return results
