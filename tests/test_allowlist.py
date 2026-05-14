import textwrap
from datetime import date
from pathlib import Path

import pytest

from afterlife.allowlist import (
    Suppression,
    apply_suppressions,
    load_allowlist,
)
from afterlife.models import Finding, Severity


def _w(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "allowlist.yaml"
    p.write_text(textwrap.dedent(body))
    return p


def _finding(**kw) -> Finding:
    defaults = dict(
        rule_id="UNUSED-CREDENTIAL",
        severity=Severity.HIGH,
        title="x",
        description="x",
        evidence={"credential_id": "AKIA-1"},
    )
    defaults.update(kw)
    return Finding(**defaults)


def test_missing_file_returns_empty(tmp_path):
    assert load_allowlist(tmp_path / "absent.yaml") == []
    assert load_allowlist(None) == []


def test_loads_flat_list(tmp_path):
    path = _w(tmp_path, """\
        - rule_id: NEVER-USED
          credential_id: AKIA-BREAKGLASS
          reason: Break-glass key
        - identity_source: google
          identity_id: g-123
          reason: New hire
    """)
    supps = load_allowlist(path)
    assert len(supps) == 2
    assert supps[0].rule_id == "NEVER-USED"
    assert supps[1].identity_source == "google"


def test_loads_wrapped_map(tmp_path):
    path = _w(tmp_path, """\
        suppressions:
          - credential_id: AKIA-X
            reason: legitimate
    """)
    supps = load_allowlist(path)
    assert len(supps) == 1
    assert supps[0].credential_id == "AKIA-X"


def test_catch_all_suppression_dropped(tmp_path):
    """An entry with no matchers would silence everything; refuse to load it."""
    path = _w(tmp_path, """\
        - reason: silence
    """)
    assert load_allowlist(path) == []


def test_invalid_top_level_raises(tmp_path):
    path = _w(tmp_path, "just a string")
    with pytest.raises(ValueError, match="top-level"):
        load_allowlist(path)


def test_until_date_parsed(tmp_path):
    path = _w(tmp_path, """\
        - credential_id: AKIA-X
          reason: temporary
          until: 2027-01-01
    """)
    supps = load_allowlist(path)
    assert supps[0].until == date(2027, 1, 1)


def test_matches_rule_id_only():
    s = Suppression(rule_id="NEVER-USED", reason="x")
    assert s.matches(_finding(rule_id="NEVER-USED"))
    assert not s.matches(_finding(rule_id="UNUSED-CREDENTIAL"))


def test_matches_credential_id_only():
    s = Suppression(credential_id="AKIA-1", reason="x")
    assert s.matches(_finding(evidence={"credential_id": "AKIA-1"}))
    assert not s.matches(_finding(evidence={"credential_id": "AKIA-OTHER"}))


def test_matches_requires_all_specified_fields():
    s = Suppression(rule_id="NEVER-USED", credential_id="AKIA-X", reason="x")
    assert not s.matches(_finding(rule_id="NEVER-USED",
                                  evidence={"credential_id": "AKIA-OTHER"}))
    assert s.matches(_finding(rule_id="NEVER-USED",
                              evidence={"credential_id": "AKIA-X"}))


def test_is_active_with_no_until():
    s = Suppression(rule_id="A", reason="x")
    assert s.is_active(date(2030, 1, 1))


def test_is_active_until_inclusive():
    s = Suppression(rule_id="A", reason="x", until=date(2026, 5, 13))
    assert s.is_active(date(2026, 5, 13))
    assert not s.is_active(date(2026, 5, 14))


def test_apply_suppressions_marks_matching_findings():
    findings = [
        _finding(rule_id="NEVER-USED", evidence={"credential_id": "AKIA-1"}),
        _finding(rule_id="UNUSED-CREDENTIAL", evidence={"credential_id": "AKIA-2"}),
    ]
    supps = [Suppression(credential_id="AKIA-1", reason="break-glass")]
    apply_suppressions(findings, supps, today=date(2026, 5, 13))
    assert findings[0].suppressed
    assert findings[0].suppression_reason == "break-glass"
    assert not findings[1].suppressed


def test_apply_suppressions_skips_expired():
    findings = [_finding(evidence={"credential_id": "AKIA-1"})]
    supps = [
        Suppression(
            credential_id="AKIA-1", reason="r", until=date(2025, 1, 1)
        )
    ]
    apply_suppressions(findings, supps, today=date(2026, 5, 13))
    assert not findings[0].suppressed
