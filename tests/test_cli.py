"""End-to-end tests for the CLI, covering exit codes."""

import pytest

from evidence_seal.cli import OK, USAGE, main


@pytest.fixture
def pkg(tmp_path):
    d = tmp_path / "aws_audit_acme_2026-01-01"
    d.mkdir()
    (d / "iam.csv").write_text("user,mfa\nalice,true\n", encoding="utf-8")
    return d


def test_seal_then_verify_intact(pkg, tmp_path):
    manifest = tmp_path / "m.json"
    assert main(["seal", str(pkg), "--out", str(manifest), "--meta", "engagement=ACME"]) == OK
    assert manifest.exists()
    assert main(["verify", str(pkg), "--manifest", str(manifest)]) == OK


def test_verify_fails_after_tamper(pkg, tmp_path):
    manifest = tmp_path / "m.json"
    main(["seal", str(pkg), "--out", str(manifest)])
    (pkg / "iam.csv").write_text("user,mfa\nalice,false\n", encoding="utf-8")
    assert main(["verify", str(pkg), "--manifest", str(manifest)]) == 1


def test_default_manifest_path(pkg):
    # No --out: manifest lands next to the dir and verify finds it by default.
    assert main(["seal", str(pkg)]) == OK
    assert (pkg.parent / f"{pkg.name}.manifest.json").exists()
    assert main(["verify", str(pkg)]) == OK


def test_manifest_inside_dir_is_not_self_sealed(pkg):
    inside = pkg / "seal.json"
    assert main(["seal", str(pkg), "--out", str(inside)]) == OK
    # Verifying still passes even though the manifest now sits inside the dir.
    assert main(["verify", str(pkg), "--manifest", str(inside)]) == OK


def test_chain_command(pkg, tmp_path):
    m1, m2 = tmp_path / "m1.json", tmp_path / "m2.json"
    main(["seal", str(pkg), "--out", str(m1)])
    (pkg / "iam.csv").write_text("user,mfa\nalice,true\nbob,true\n", encoding="utf-8")
    main(["seal", str(pkg), "--out", str(m2), "--prev", str(m1)])
    assert main(["chain", str(m1), str(m2)]) == OK
    assert main(["chain", str(m2), str(m1)]) == 1


def test_bad_metadata_is_usage_error(pkg, tmp_path):
    assert main(["seal", str(pkg), "--out", str(tmp_path / "m.json"), "--meta", "novalue"]) == USAGE


def test_sign_and_verify_via_cli(pkg, tmp_path):
    pytest.importorskip("cryptography")
    priv, pub = tmp_path / "k.key", tmp_path / "k.pub"
    assert main(["keygen", "--private", str(priv), "--public", str(pub)]) == OK
    manifest = tmp_path / "m.json"
    assert main(["seal", str(pkg), "--out", str(manifest), "--sign", str(priv)]) == OK
    assert main(["verify", str(pkg), "--manifest", str(manifest), "--pubkey", str(pub)]) == OK


def test_verify_rejects_wrong_signer(pkg, tmp_path):
    pytest.importorskip("cryptography")
    priv, pub = tmp_path / "k.key", tmp_path / "k.pub"
    other_pub = tmp_path / "o.pub"
    main(["keygen", "--private", str(priv), "--public", str(pub)])
    main(["keygen", "--private", str(tmp_path / "o.key"), "--public", str(other_pub)])
    manifest = tmp_path / "m.json"
    main(["seal", str(pkg), "--out", str(manifest), "--sign", str(priv)])
    assert main(["verify", str(pkg), "--manifest", str(manifest), "--pubkey", str(other_pub)]) == 1
