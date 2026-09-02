"""Jira ticketing integration (Pro): delivery, config, and license gating."""

import json

import httpx
import pytest
import respx
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from afterlife.db import ReconcileSummary
from afterlife.licensing import issue_license
from afterlife.models import Finding, Severity, finding_fingerprint
from afterlife.notify import (
    Alert,
    JiraNotifier,
    JiraSettings,
    NotifyConfig,
    notify_findings,
)

JIRA = "https://acme.atlassian.net"
ISSUE_URL = JIRA + "/rest/api/3/issue"


def _keypair():
    p = Ed25519PrivateKey.generate()
    return (
        p.private_bytes(
            ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()
        ).decode(),
        p.public_key()
        .public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)
        .decode(),
    )


def _settings():
    return JiraSettings(
        base_url=JIRA, email="bot@acme.com", api_token="tok", project_key="SEC"
    )


def _f(cid, sev=Severity.CRITICAL):
    return Finding(
        rule_id="OFFBOARDED-OWNER", severity=sev, title=f"finding {cid}",
        description="d", evidence={"credential_id": cid},
    )


def _summary(new):
    s = ReconcileSummary()
    s.new_fingerprints = {finding_fingerprint(f) for f in new}
    s.new = len(new)
    return s


# ---------- delivery ----------


@respx.mock
def test_jira_creates_issue():
    route = respx.post(ISSUE_URL).mock(return_value=httpx.Response(201, json={"key": "SEC-1"}))
    JiraNotifier(_settings()).send(Alert(findings=[_f("C1")], new_count=1))
    assert route.called
    req = route.calls.last.request
    assert req.headers["authorization"].startswith("Basic ")  # email:token basic auth
    body = json.loads(req.content)
    assert body["fields"]["project"]["key"] == "SEC"
    assert body["fields"]["issuetype"]["name"] == "Task"
    assert body["fields"]["summary"].startswith("Afterlife:")
    assert body["fields"]["description"]["type"] == "doc"  # ADF


@respx.mock
def test_jira_raises_on_api_error():
    respx.post(ISSUE_URL).mock(return_value=httpx.Response(400, json={"errors": {}}))
    with pytest.raises(httpx.HTTPStatusError):
        JiraNotifier(_settings()).send(Alert(findings=[_f("C1")], new_count=1))


# ---------- config ----------


def test_from_env_parses_jira():
    env = {
        "AFTERLIFE_JIRA_URL": JIRA, "AFTERLIFE_JIRA_EMAIL": "b@acme.com",
        "AFTERLIFE_JIRA_TOKEN": "t", "AFTERLIFE_JIRA_PROJECT": "SEC",
    }
    c = NotifyConfig.from_env(env)
    assert c.jira is not None
    assert c.jira.project_key == "SEC"
    assert c.has_channels()


def test_from_env_jira_needs_every_field():
    c = NotifyConfig.from_env({"AFTERLIFE_JIRA_URL": JIRA})  # incomplete
    assert c.jira is None


# ---------- license gating ----------


def test_jira_gated_off_without_license(monkeypatch):
    monkeypatch.delenv("AFTERLIFE_LICENSE", raising=False)
    c = NotifyConfig(jira=_settings(), min_severity=Severity.HIGH)
    assert c.build_notifiers(env={}) == []
    assert c.unlicensed_pro_channels(env={}) == ["jira"]


def test_jira_enabled_with_pro_license(monkeypatch):
    priv, pub = _keypair()
    monkeypatch.setattr("afterlife.licensing.VENDOR_PUBLIC_KEY", pub)
    token = issue_license(priv, "Acme")
    c = NotifyConfig(jira=_settings(), min_severity=Severity.HIGH)
    built = c.build_notifiers(env={"AFTERLIFE_LICENSE": token})
    assert [n.name for n in built] == ["jira"]
    assert c.unlicensed_pro_channels(env={"AFTERLIFE_LICENSE": token}) == []


def test_notify_findings_upsells_when_unlicensed(monkeypatch):
    monkeypatch.delenv("AFTERLIFE_LICENSE", raising=False)
    c = NotifyConfig(jira=_settings(), min_severity=Severity.HIGH)
    f = _f("C1")
    res = notify_findings([f], _summary([f]), c)
    assert "requires a Pro license" in res["jira"]


@respx.mock
def test_notify_findings_files_ticket_when_licensed(monkeypatch):
    respx.post(ISSUE_URL).mock(return_value=httpx.Response(201, json={"key": "SEC-2"}))
    priv, pub = _keypair()
    monkeypatch.setattr("afterlife.licensing.VENDOR_PUBLIC_KEY", pub)
    monkeypatch.setenv("AFTERLIFE_LICENSE", issue_license(priv, "Acme"))
    c = NotifyConfig(jira=_settings(), min_severity=Severity.HIGH)
    f = _f("C1")
    res = notify_findings([f], _summary([f]), c)
    assert res["jira"] == "sent"
