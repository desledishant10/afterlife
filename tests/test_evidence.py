"""Signed, tamper-evident audit-evidence packs and their CLI."""

import base64
import json
import os
import stat

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typer.testing import CliRunner

from afterlife import db
from afterlife.cli import app
from afterlife.evidence import (
    SCHEMA,
    default_key_path,
    fingerprint,
    generate_evidence,
    load_pack,
    render_html,
    sign_payload,
    verify_evidence,
)
from afterlife.models import Finding, Severity

runner = CliRunner()


def _seed_open(db_path, rule_id="UNUSED-CREDENTIAL", cred="AKIA-1"):
    with db.connect(db_path) as conn:
        db.insert_finding(
            conn,
            Finding(
                rule_id=rule_id,
                severity=Severity.HIGH,
                title="Old key idle 120d",
                description="An access key has been idle.",
                evidence={"credential_id": cred},
            ),
        )


def _seed_resolved(db_path, *, first_seen, resolved_at, rule_id="NEVER-USED"):
    with db.connect(db_path) as conn:
        db.insert_finding(
            conn,
            Finding(
                rule_id=rule_id,
                severity=Severity.MEDIUM,
                title="Never used credential",
                description="d",
                evidence={"credential_id": "R-1"},
            ),
        )
        conn.execute(
            "UPDATE findings SET status='resolved', first_seen=?, resolved_at=? "
            "WHERE rule_id=?",
            (first_seen, resolved_at, rule_id),
        )


# ---------- core sign / verify ----------


def test_generate_and_verify_roundtrip(fresh_db, tmp_path):
    _seed_open(fresh_db)
    key = tmp_path / "att.pem"
    pack = generate_evidence(fresh_db, key_path=key)
    ok, payload, reason = verify_evidence(pack)
    assert ok, reason
    assert payload["summary"]["open_total"] == 1
    assert pack["algorithm"] == "Ed25519"
    assert key.exists()  # attestation key auto-created


def test_empty_db_produces_valid_pack(fresh_db, tmp_path):
    pack = generate_evidence(fresh_db, key_path=tmp_path / "k.pem")
    ok, payload, _ = verify_evidence(pack)
    assert ok
    assert payload["summary"]["open_total"] == 0


def test_tampered_payload_fails(fresh_db, tmp_path):
    _seed_open(fresh_db)
    pack = generate_evidence(fresh_db, key_path=tmp_path / "k.pem")
    pack["payload"]["summary"]["open_total"] = 999  # tamper the content
    ok, _, reason = verify_evidence(pack)
    assert not ok
    assert "tamper" in reason or "hash" in reason or "signature" in reason


def test_tampered_signature_fails(fresh_db, tmp_path):
    _seed_open(fresh_db)
    pack = generate_evidence(fresh_db, key_path=tmp_path / "k.pem")
    raw = bytearray(base64.b64decode(pack["signature"]))
    raw[0] ^= 0x01  # flip a bit; content hash still matches, signature will not
    pack["signature"] = base64.b64encode(bytes(raw)).decode()
    ok, _, reason = verify_evidence(pack)
    assert not ok
    assert "signature" in reason


def test_wrong_key_swapped_in_fails(fresh_db, tmp_path):
    # Swapping in a different public key must not verify a foreign signature.
    _seed_open(fresh_db)
    pack = generate_evidence(fresh_db, key_path=tmp_path / "a.pem")
    other = generate_evidence(fresh_db, key_path=tmp_path / "b.pem")
    pack["public_key"] = other["public_key"]
    ok, _, _ = verify_evidence(pack)
    assert not ok


def test_key_reused_and_mode_600(fresh_db, tmp_path):
    key = tmp_path / "att.pem"
    p1 = generate_evidence(fresh_db, key_path=key)
    p2 = generate_evidence(fresh_db, key_path=key)
    assert p1["public_key"] == p2["public_key"]  # stable across packs
    assert stat.S_IMODE(os.stat(key).st_mode) == 0o600


def test_default_key_path_sits_next_to_db(tmp_path):
    dbp = tmp_path / "sub" / "afterlife.db"
    kp = default_key_path(dbp)
    assert kp.name == ".afterlife-attestation-key.pem"
    assert kp.parent == (tmp_path / "sub").resolve()


def test_mttr_and_resolved_counted(fresh_db, tmp_path):
    _seed_resolved(
        fresh_db,
        first_seen="2026-01-01T00:00:00+00:00",
        resolved_at="2026-01-11T00:00:00+00:00",
    )
    pack = generate_evidence(fresh_db, key_path=tmp_path / "k.pem")
    s = pack["payload"]["summary"]
    assert s["resolved_total"] == 1
    assert s["mean_time_to_remediate_days"] == 10.0


# ---------- html embed round-trip ----------


def test_html_render_embeds_verifiable_pack(fresh_db, tmp_path):
    _seed_open(fresh_db)
    pack = generate_evidence(fresh_db, key_path=tmp_path / "k.pem")
    html = render_html(pack)
    p = tmp_path / "ev.html"
    p.write_text(html)
    reloaded = load_pack(p)
    ok, _, _ = verify_evidence(reloaded)
    assert ok
    assert "Access-review attestation" in html
    assert fingerprint(pack["public_key"]) in html


# ---------- CLI: gating + free verification ----------


def test_evidence_cli_refused_without_license(fresh_db, tmp_path, monkeypatch):
    monkeypatch.delenv("AFTERLIFE_LICENSE", raising=False)
    monkeypatch.delenv("AFTERLIFE_LICENSE_FILE", raising=False)
    out = tmp_path / "ev.json"
    result = runner.invoke(
        app, ["evidence", "--db-path", str(fresh_db), "-o", str(out)]
    )
    assert result.exit_code == 1
    assert "Pro feature" in result.stdout
    assert not out.exists()


def test_evidence_cli_writes_with_license(fresh_db, tmp_path, monkeypatch):
    import afterlife.licensing as lic
    monkeypatch.setattr(lic, "has_feature", lambda feature, env=None: True)
    _seed_open(fresh_db)
    out = tmp_path / "ev.json"
    result = runner.invoke(
        app,
        [
            "evidence", "--db-path", str(fresh_db),
            "-o", str(out), "--key-file", str(tmp_path / "k.pem"),
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert out.exists()
    ok, _, _ = verify_evidence(json.loads(out.read_text()))
    assert ok


def test_verify_evidence_cli_is_free(fresh_db, tmp_path, monkeypatch):
    _seed_open(fresh_db)
    pack = generate_evidence(fresh_db, key_path=tmp_path / "k.pem")
    out = tmp_path / "ev.json"
    out.write_text(json.dumps(pack))
    monkeypatch.delenv("AFTERLIFE_LICENSE", raising=False)  # no license needed
    result = runner.invoke(app, ["verify-evidence", str(out)])
    assert result.exit_code == 0
    assert "VALID" in result.stdout


def test_verify_evidence_cli_detects_tamper(fresh_db, tmp_path):
    _seed_open(fresh_db)
    pack = generate_evidence(fresh_db, key_path=tmp_path / "k.pem")
    pack["payload"]["open_findings"][0]["severity"] = "low"  # tamper
    out = tmp_path / "ev.json"
    out.write_text(json.dumps(pack))
    result = runner.invoke(app, ["verify-evidence", str(out)])
    assert result.exit_code == 1
    assert "INVALID" in result.stdout


# ---------- security-review hardening ----------


def test_fingerprint_is_full_sha256(fresh_db, tmp_path):
    pack = generate_evidence(fresh_db, key_path=tmp_path / "k.pem")
    fp = fingerprint(pack["public_key"])
    assert len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp)


def test_verify_rejects_malformed_public_key_without_crashing():
    base = {
        "payload": {"schema": SCHEMA, "attestation_id": "x",
                    "generated_at": "t", "summary": {}},
        "signature": "AA==",
    }
    for bad in (None, 123, ["x"], {"k": "v"}, "not a pem"):
        ok, payload, reason = verify_evidence({**base, "public_key": bad})
        assert ok is False and payload is None  # returns cleanly, no traceback


def test_verify_rejects_non_dict_pack():
    for bad in (None, "x", 5, [1, 2]):
        ok, _, _ = verify_evidence(bad)
        assert ok is False


def test_verify_rejects_signed_but_schemaless_payload():
    # A validly-signed payload that is not a real evidence payload must fail,
    # so the caller never gets ok=True (and never prints VALID then crashes).
    key = Ed25519PrivateKey.generate()
    pack = sign_payload({}, key)
    ok, payload, reason = verify_evidence(pack)
    assert not ok
    assert "schema" in reason or "required" in reason


def test_verify_cli_pin_match(fresh_db, tmp_path):
    _seed_open(fresh_db)
    pack = generate_evidence(fresh_db, key_path=tmp_path / "k.pem")
    out = tmp_path / "ev.json"
    out.write_text(json.dumps(pack))
    result = runner.invoke(
        app, ["verify-evidence", str(out), "--pin", fingerprint(pack["public_key"])]
    )
    assert result.exit_code == 0, result.stdout
    assert "Origin TRUSTED" in result.stdout


def test_verify_cli_pin_mismatch_fails(fresh_db, tmp_path):
    _seed_open(fresh_db)
    pack = generate_evidence(fresh_db, key_path=tmp_path / "k.pem")
    out = tmp_path / "ev.json"
    out.write_text(json.dumps(pack))
    result = runner.invoke(
        app, ["verify-evidence", str(out), "--pin", "deadbeef" * 8]
    )
    assert result.exit_code == 2
    assert "UNVERIFIED" in result.stdout


def test_verify_cli_without_pin_warns_origin_unverified(fresh_db, tmp_path):
    _seed_open(fresh_db)
    pack = generate_evidence(fresh_db, key_path=tmp_path / "k.pem")
    out = tmp_path / "ev.json"
    out.write_text(json.dumps(pack))
    result = runner.invoke(app, ["verify-evidence", str(out)])
    assert result.exit_code == 0
    assert "unverified" in result.stdout.lower()


def test_key_created_600_even_under_permissive_umask(fresh_db, tmp_path):
    old = os.umask(0o000)  # force a permissive umask; atomic create must still be 600
    try:
        key = tmp_path / "att.pem"
        generate_evidence(fresh_db, key_path=key)
        assert stat.S_IMODE(os.stat(key).st_mode) == 0o600
    finally:
        os.umask(old)
