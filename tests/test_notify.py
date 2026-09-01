"""Alerting: finding selection, per-channel delivery, and dispatch."""

import json
from unittest.mock import patch

import httpx
import pytest
import respx

from afterlife.db import ReconcileSummary
from afterlife.models import Finding, Severity, finding_fingerprint
from afterlife.notify import (
    Alert,
    EmailNotifier,
    NotifyConfig,
    SlackNotifier,
    SMTPSettings,
    WebhookNotifier,
    notify_findings,
    select_alertable,
)

SLACK_URL = "https://hooks.slack.com/services/T/B/xyz"
WEBHOOK_URL = "https://hooks.example.com/afterlife"


def _f(credential_id, severity, *, rule="OFFBOARDED-OWNER", title=None):
    return Finding(
        rule_id=rule,
        severity=severity,
        title=title or f"finding {credential_id}",
        description="d",
        evidence={"credential_id": credential_id},
    )


def _summary(*, new=(), reopened=()):
    s = ReconcileSummary()
    s.new_fingerprints = {finding_fingerprint(f) for f in new}
    s.reopened_fingerprints = {finding_fingerprint(f) for f in reopened}
    s.new = len(new)
    s.reopened = len(reopened)
    return s


# ---------- selection ----------


def test_select_alertable_picks_new_and_reopened_above_threshold():
    crit = _f("C1", Severity.CRITICAL)
    high = _f("C2", Severity.HIGH)
    med = _f("C3", Severity.MEDIUM)  # below "high" threshold
    ongoing = _f("C4", Severity.CRITICAL)  # not in the changed set
    findings = [crit, high, med, ongoing]
    summary = _summary(new=[crit, med], reopened=[high])

    alert = select_alertable(findings, summary, Severity.HIGH)

    assert {f.evidence["credential_id"] for f in alert.findings} == {"C1", "C2"}
    assert alert.new_count == 1
    assert alert.reopened_count == 1


def test_select_alertable_skips_suppressed():
    f = _f("C1", Severity.CRITICAL)
    f.suppressed = True
    alert = select_alertable([f], _summary(new=[f]), Severity.HIGH)
    assert not alert


def test_select_alertable_respects_min_severity():
    low = _f("C1", Severity.LOW)
    alert = select_alertable([low], _summary(new=[low]), Severity.LOW)
    assert len(alert.findings) == 1
    alert_high = select_alertable([low], _summary(new=[low]), Severity.HIGH)
    assert not alert_high


def test_alert_title_and_lines_order():
    high = _f("C2", Severity.HIGH, title="high one")
    crit = _f("C1", Severity.CRITICAL, title="crit one")
    alert = Alert(findings=[high, crit], new_count=1, reopened_count=1)
    assert "1 new and 1 reopened" in alert.title()
    # Critical is listed before high.
    assert alert.lines()[0].startswith("[CRITICAL]")


# ---------- channels ----------


@respx.mock
def test_webhook_posts_payload():
    route = respx.post(WEBHOOK_URL).mock(return_value=httpx.Response(200))
    alert = Alert(findings=[_f("C1", Severity.CRITICAL)], new_count=1)
    WebhookNotifier(WEBHOOK_URL).send(alert)
    assert route.called
    body = json.loads(route.calls.last.request.content)
    assert body["source"] == "afterlife"
    assert body["new"] == 1
    assert body["findings"][0]["severity"] == "critical"


@respx.mock
def test_webhook_raises_on_http_error():
    respx.post(WEBHOOK_URL).mock(return_value=httpx.Response(500))
    with pytest.raises(httpx.HTTPStatusError):
        WebhookNotifier(WEBHOOK_URL).send(
            Alert(findings=[_f("C1", Severity.HIGH)], new_count=1)
        )


@respx.mock
def test_slack_posts_text_and_blocks():
    route = respx.post(SLACK_URL).mock(return_value=httpx.Response(200))
    alert = Alert(findings=[_f("C1", Severity.CRITICAL)], new_count=1)
    SlackNotifier(SLACK_URL).send(alert)
    body = json.loads(route.calls.last.request.content)
    assert "text" in body
    assert body["blocks"][0]["type"] == "header"


@patch("afterlife.notify.email.smtplib.SMTP")
def test_email_sends_message(mock_smtp):
    server = mock_smtp.return_value.__enter__.return_value
    settings = SMTPSettings(
        host="smtp.example.com",
        username="u",
        password="p",
        sender="afterlife@example.com",
        recipients=["sec@example.com"],
    )
    EmailNotifier(settings).send(
        Alert(findings=[_f("C1", Severity.CRITICAL)], new_count=1)
    )
    server.starttls.assert_called_once()
    server.login.assert_called_once_with("u", "p")
    server.send_message.assert_called_once()
    msg = server.send_message.call_args[0][0]
    assert msg["To"] == "sec@example.com"
    assert "Afterlife" in msg["Subject"]


# ---------- dispatch ----------


@respx.mock
def test_notify_findings_dispatches_and_reports_failures():
    respx.post(SLACK_URL).mock(return_value=httpx.Response(200))
    respx.post(WEBHOOK_URL).mock(return_value=httpx.Response(503))
    config = NotifyConfig(
        slack_webhook=SLACK_URL,
        webhook_url=WEBHOOK_URL,
        min_severity=Severity.HIGH,
    )
    f = _f("C1", Severity.CRITICAL)
    results = notify_findings([f], _summary(new=[f]), config)
    assert results["slack"] == "sent"
    assert results["webhook"].startswith("error")


def test_notify_findings_empty_when_nothing_alertable():
    config = NotifyConfig(webhook_url=WEBHOOK_URL, min_severity=Severity.HIGH)
    low = _f("C1", Severity.LOW)  # below threshold, so nothing to send
    assert notify_findings([low], _summary(new=[low]), config) == {}


# ---------- config ----------


def test_notify_config_from_env_builds_all_channels():
    env = {
        "AFTERLIFE_SLACK_WEBHOOK": SLACK_URL,
        "AFTERLIFE_WEBHOOK_URL": WEBHOOK_URL,
        "AFTERLIFE_SMTP_HOST": "smtp.example.com",
        "AFTERLIFE_SMTP_PORT": "2525",
        "AFTERLIFE_EMAIL_FROM": "afterlife@example.com",
        "AFTERLIFE_EMAIL_TO": "a@example.com, b@example.com",
        "AFTERLIFE_NOTIFY_MIN_SEVERITY": "critical",
    }
    c = NotifyConfig.from_env(env)
    assert c.slack_webhook == SLACK_URL
    assert c.webhook_url == WEBHOOK_URL
    assert c.min_severity == Severity.CRITICAL
    assert c.smtp is not None
    assert c.smtp.port == 2525
    assert c.smtp.recipients == ["a@example.com", "b@example.com"]
    assert c.has_channels()
    assert {n.name for n in c.build_notifiers()} == {"slack", "webhook", "email"}


def test_notify_config_empty_env_has_no_channels():
    c = NotifyConfig.from_env({})
    assert not c.has_channels()
    assert c.min_severity == Severity.HIGH
    assert c.build_notifiers() == []


def test_notify_config_email_needs_host_and_recipients():
    # host without recipients -> no smtp channel
    c = NotifyConfig.from_env({"AFTERLIFE_SMTP_HOST": "smtp.example.com"})
    assert c.smtp is None
