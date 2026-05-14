from afterlife.models import Credential
from afterlife.scoring.blast_radius import score


def _cred(credential_type: str, **kw) -> Credential:
    defaults = dict(
        source="aws",
        credential_id="cred-1",
        credential_type=credential_type,
        scopes=[],
        metadata={},
    )
    defaults.update(kw)
    return Credential(**defaults)


def test_unknown_type_gets_default_prior():
    b = score(_cred("unknown_type"))
    assert b.score == 0.30
    assert b.label == "limited"


def test_aws_access_key_baseline():
    b = score(_cred("aws_access_key"))
    assert b.score == 0.55
    assert b.label == "moderate"


def test_github_deploy_key_read_only_is_limited():
    b = score(_cred("github_deploy_key", scopes=["read"]))
    assert b.score == 0.20
    assert b.label == "limited"


def test_github_deploy_key_with_write_is_higher():
    b = score(_cred("github_deploy_key", scopes=["read", "write"]))
    # 0.20 + 0.20 (deploy-key write bump) = 0.40, moderate
    assert b.score >= 0.40
    assert b.label == "moderate"
    assert any("write" in f.lower() for f in b.factors)


def test_administrator_access_lifts_to_broad():
    b = score(_cred("aws_access_key", scopes=["AdministratorAccess"]))
    # 0.55 + 0.30 (elevated) = 0.85, broad
    assert b.score >= 0.70
    assert b.label == "broad"
    assert any("elevated" in f.lower() for f in b.factors)


def test_readonly_access_lowers_score():
    b = score(_cred("aws_access_key", scopes=["ReadOnlyAccess"]))
    # 0.55 - 0.15 = 0.40, moderate
    assert b.score < 0.55
    assert any("read-only" in f.lower() for f in b.factors)


def test_elevated_and_readonly_does_not_double_dip():
    """If both signals are present, elevated wins (no readonly subtraction)."""
    b = score(
        _cred("aws_access_key", scopes=["AdministratorAccess", "ReadOnlyAccess"])
    )
    # Elevated bump should apply, readonly bump should not
    assert b.score >= 0.70


def test_many_scopes_count_as_broad():
    scopes = ["scope_a", "scope_b", "scope_c", "scope_d", "scope_e", "scope_f"]
    b = score(_cred("aws_iam_role", scopes=scopes))
    # 0.50 base + 0.10 (>=5 scopes) = 0.60
    assert b.score == 0.60


def test_factors_explain_score():
    b = score(_cred("aws_access_key", scopes=["AdministratorAccess"]))
    joined = " ".join(b.factors).lower()
    assert "aws_access_key" in joined
    assert "elevated" in joined or "administrator" in joined


def test_score_clamped_to_one():
    # Construct a worst-case credential
    scopes = ["AdministratorAccess", "FullAccess", "*:*"] + [f"s{i}" for i in range(10)]
    b = score(_cred("aws_access_key", scopes=scopes, metadata={"is_admin": True}))
    assert b.score <= 1.0
    assert b.label == "broad"


def test_admin_metadata_flag_lifts_score():
    b = score(_cred("aws_iam_role", metadata={"is_admin": True}))
    # 0.50 + 0.15 (admin flag) = 0.65
    assert b.score == 0.65
    assert any("admin" in f.lower() for f in b.factors)


def test_label_thresholds():
    from afterlife.models import BlastRadius

    assert BlastRadius(score=0.95).label == "broad"
    assert BlastRadius(score=0.70).label == "broad"
    assert BlastRadius(score=0.69).label == "moderate"
    assert BlastRadius(score=0.40).label == "moderate"
    assert BlastRadius(score=0.39).label == "limited"
    assert BlastRadius(score=0.00).label == "limited"
