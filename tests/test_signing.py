"""Tests for optional ed25519 signing (skipped if cryptography is absent)."""

import pytest

pytest.importorskip("cryptography")

from evidence_seal.manifest import build_manifest
from evidence_seal.signing import (
    generate_keypair,
    load_public_hex,
    sign_manifest,
    verify_signature,
)


@pytest.fixture
def sealed(tmp_path):
    d = tmp_path / "pkg"
    d.mkdir()
    (d / "a.csv").write_text("x\n", encoding="utf-8")
    return build_manifest(d)


@pytest.fixture
def keys(tmp_path):
    priv, pub = tmp_path / "k.key", tmp_path / "k.pub"
    generate_keypair(priv, pub)
    return priv, pub


def test_sign_then_verify(sealed, keys):
    priv, pub = keys
    signed = sign_manifest(sealed, priv)
    ok, _ = verify_signature(signed)
    assert ok
    # And the embedded key matches the PEM public key.
    ok_matched, _ = verify_signature(signed, load_public_hex(pub))
    assert ok_matched


def test_unsigned_manifest_reports_clearly(sealed):
    ok, message = verify_signature(sealed)
    assert not ok
    assert "not signed" in message


def test_tampered_manifest_fails_signature(sealed, keys):
    priv, _ = keys
    signed = sign_manifest(sealed, priv)
    # Alter a hash after signing; the signature no longer covers it.
    signed["files"][0]["sha256"] = "0" * 64
    ok, _ = verify_signature(signed)
    assert not ok


def test_wrong_expected_key_rejected(sealed, tmp_path, keys):
    priv, _ = keys
    signed = sign_manifest(sealed, priv)
    other_priv, other_pub = tmp_path / "o.key", tmp_path / "o.pub"
    generate_keypair(other_priv, other_pub)
    ok, message = verify_signature(signed, load_public_hex(other_pub))
    assert not ok
    assert "does not match" in message
