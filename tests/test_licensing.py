"""Offline license verification, feature gating, and the license CLI."""

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typer.testing import CliRunner

from afterlife import db
from afterlife.cli import app
from afterlife.licensing import (
    FEATURE_DASHBOARD_AUTH,
    License,
    edition,
    has_feature,
    issue_license,
    load_license_token,
    verify_license,
)

runner = CliRunner()


def _keypair() -> tuple[str, str]:
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()
    ).decode()
    pub_pem = (
        priv.public_key()
        .public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    return priv_pem, pub_pem


# ---------- sign / verify ----------


def test_issue_and_verify_roundtrip():
    priv, pub = _keypair()
    lic = verify_license(issue_license(priv, "Acme Corp", expires_in_days=365), pub)
    assert lic is not None
    assert lic.is_pro
    assert lic.customer == "Acme Corp"
    assert lic.expires_at is not None
    assert lic.grants(FEATURE_DASHBOARD_AUTH)


def test_perpetual_license_has_no_expiry():
    priv, pub = _keypair()
    lic = verify_license(issue_license(priv, "X", expires_in_days=None), pub)
    assert lic is not None
    assert lic.expires_at is None


def test_expired_license_rejected():
    priv, pub = _keypair()
    assert verify_license(issue_license(priv, "X", expires_in_days=-1), pub) is None


def test_license_signed_by_other_key_rejected():
    priv, _ = _keypair()
    _, other_pub = _keypair()
    assert verify_license(issue_license(priv, "X"), other_pub) is None


def test_garbage_tokens_rejected():
    assert verify_license("not.a.jwt") is None
    assert verify_license("") is None


# ---------- feature grants ----------


def test_free_license_grants_nothing():
    assert License(customer="x", edition="free").grants(FEATURE_DASHBOARD_AUTH) is False


def test_pro_without_feature_list_grants_all():
    assert License(customer="x", edition="pro", features=[]).grants(FEATURE_DASHBOARD_AUTH)


def test_pro_with_feature_list_is_scoped():
    lic = License(customer="x", edition="pro", features=["something_else"])
    assert lic.grants(FEATURE_DASHBOARD_AUTH) is False


# ---------- token loading + edition ----------


def test_load_token_from_env_is_stripped():
    assert load_license_token({"AFTERLIFE_LICENSE": "  tok  "}) == "tok"


def test_load_token_from_file(tmp_path):
    p = tmp_path / "lic.jwt"
    p.write_text("filetoken\n")
    assert load_license_token({"AFTERLIFE_LICENSE_FILE": str(p)}) == "filetoken"


def test_load_token_absent():
    assert load_license_token({}) is None


def test_free_edition_by_default():
    assert edition({}) == "free"
    assert has_feature(FEATURE_DASHBOARD_AUTH, env={}) is False


def test_pro_edition_via_env(monkeypatch):
    priv, pub = _keypair()
    monkeypatch.setattr("afterlife.licensing.VENDOR_PUBLIC_KEY", pub)
    token = issue_license(priv, "Acme")
    assert edition({"AFTERLIFE_LICENSE": token}) == "pro"
    assert has_feature(FEATURE_DASHBOARD_AUTH, env={"AFTERLIFE_LICENSE": token})


# ---------- CLI ----------


def test_license_command_free(monkeypatch):
    monkeypatch.delenv("AFTERLIFE_LICENSE", raising=False)
    monkeypatch.delenv("AFTERLIFE_LICENSE_FILE", raising=False)
    result = runner.invoke(app, ["license"])
    assert result.exit_code == 0
    assert "Free" in result.stdout


def test_license_command_free_shows_get_pro_cta(monkeypatch):
    from afterlife.licensing import PRO_CONTACT
    monkeypatch.delenv("AFTERLIFE_LICENSE", raising=False)
    monkeypatch.delenv("AFTERLIFE_LICENSE_FILE", raising=False)
    result = runner.invoke(app, ["license"])
    assert "Get Pro" in result.stdout
    assert "$990" in result.stdout
    assert PRO_CONTACT in result.stdout


def test_license_command_pro(monkeypatch):
    priv, pub = _keypair()
    monkeypatch.setattr("afterlife.licensing.VENDOR_PUBLIC_KEY", pub)
    monkeypatch.setenv("AFTERLIFE_LICENSE", issue_license(priv, "AcmeCorp"))
    result = runner.invoke(app, ["license"])
    assert result.exit_code == 0
    assert "Pro" in result.stdout
    assert "AcmeCorp" in result.stdout


def test_serve_require_auth_refused_without_license(monkeypatch, tmp_path):
    monkeypatch.delenv("AFTERLIFE_LICENSE", raising=False)
    dbp = tmp_path / "a.db"
    db.init_db(dbp)
    result = runner.invoke(
        app, ["serve", "--db-path", str(dbp), "--require-auth", "--password", "x"]
    )
    assert result.exit_code == 1
    assert "Pro" in result.stdout


# ---------- jti / revocation ----------


def test_minted_token_has_unique_jti():
    priv, pub = _keypair()
    a = verify_license(issue_license(priv, "Acme"), pub)
    b = verify_license(issue_license(priv, "Acme"), pub)
    assert a is not None and b is not None
    assert a.jti and b.jti
    assert a.jti != b.jti  # each mint is individually revocable


def test_denylisted_jti_is_rejected():
    priv, pub = _keypair()
    token = issue_license(priv, "Acme", jti="revoke-me")
    assert verify_license(token, pub) is not None  # valid without a denylist
    assert verify_license(token, pub, denylist={"revoke-me"}) is None
    # An unrelated jti on the list does not affect this token.
    assert verify_license(token, pub, denylist={"other"}) is not None


def test_current_license_respects_denylist_env(monkeypatch):
    from afterlife.licensing import current_license
    priv, pub = _keypair()
    monkeypatch.setattr("afterlife.licensing.VENDOR_PUBLIC_KEY", pub)
    monkeypatch.setenv("AFTERLIFE_LICENSE", issue_license(priv, "Acme", jti="abc123"))
    monkeypatch.delenv("AFTERLIFE_LICENSE_FILE", raising=False)
    assert current_license() is not None
    monkeypatch.setenv("AFTERLIFE_LICENSE_DENYLIST", "zzz, abc123 , yyy")
    assert current_license() is None


def test_denylist_from_file(tmp_path, monkeypatch):
    from afterlife.licensing import current_license
    priv, pub = _keypair()
    monkeypatch.setattr("afterlife.licensing.VENDOR_PUBLIC_KEY", pub)
    monkeypatch.setenv("AFTERLIFE_LICENSE", issue_license(priv, "Acme", jti="file-jti"))
    monkeypatch.delenv("AFTERLIFE_LICENSE_FILE", raising=False)
    dl = tmp_path / "revoked.txt"
    dl.write_text("# revoked licenses\nfile-jti\n")
    monkeypatch.setenv("AFTERLIFE_LICENSE_DENYLIST_FILE", str(dl))
    assert current_license() is None


def test_token_without_jti_still_verifies():
    # Backward compatibility: licenses minted before jti existed have no jti and
    # must still verify (they simply cannot be revoked by jti).
    import jwt
    priv, pub = _keypair()
    token = jwt.encode({"sub": "OldCorp", "edition": "pro"}, priv, algorithm="EdDSA")
    lic = verify_license(token, pub, denylist={"anything"})
    assert lic is not None
    assert lic.jti is None
    assert lic.is_pro


def test_baked_in_revocation_is_enforced(monkeypatch):
    from afterlife import licensing
    priv, pub = _keypair()
    monkeypatch.setattr(licensing, "VENDOR_PUBLIC_KEY", pub)
    monkeypatch.setattr(licensing, "_REVOKED_JTIS", frozenset({"baked"}))
    monkeypatch.setenv("AFTERLIFE_LICENSE", issue_license(priv, "Acme", jti="baked"))
    monkeypatch.delenv("AFTERLIFE_LICENSE_FILE", raising=False)
    monkeypatch.delenv("AFTERLIFE_LICENSE_DENYLIST", raising=False)
    assert licensing.current_license() is None
