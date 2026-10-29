"""Tests for SSH signatures, including interoperability with OpenSSH."""

import shutil
import subprocess

import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from evidence_seal import sshsig

NS = "test@audit-labs"


@pytest.fixture
def key():
    return ed25519.Ed25519PrivateKey.generate()


def test_sign_verify_roundtrip(key):
    sig = sshsig.sign(b"hello", key, NS)
    assert sig.startswith("-----BEGIN SSH SIGNATURE-----")
    assert sshsig.verify(b"hello", sig, NS) == sshsig.raw_public_key(key)


def test_wrong_message_namespace_or_garbage_fails(key):
    sig = sshsig.sign(b"hello", key, NS)
    with pytest.raises(sshsig.SignatureError):
        sshsig.verify(b"hellO", sig, NS)
    with pytest.raises(sshsig.SignatureError, match="namespace"):
        sshsig.verify(b"hello", sig, "other@audit-labs")
    with pytest.raises(sshsig.SignatureError):
        sshsig.verify(b"hello", "not a signature", NS)


def test_public_key_line_and_fingerprint(key):
    raw = sshsig.raw_public_key(key)
    line = sshsig.format_public_key(raw, "alice")
    assert sshsig.parse_public_key(line) == raw
    assert sshsig.fingerprint(raw).startswith("SHA256:")
    with pytest.raises(sshsig.SignatureError):
        sshsig.parse_public_key("ssh-rsa AAAA")


def test_encrypted_pem_key_loads_with_passphrase(tmp_path, key):
    path = tmp_path / "k.pem"
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"secret"),
        )
    )
    with pytest.raises(TypeError):
        sshsig.load_private_key(path)
    loaded = sshsig.load_private_key(path, b"secret")
    assert sshsig.raw_public_key(loaded) == sshsig.raw_public_key(key)


@pytest.mark.skipif(not shutil.which("ssh-keygen"), reason="ssh-keygen not installed")
def test_interoperates_with_ssh_keygen(tmp_path):
    keyfile = tmp_path / "id_ed25519"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(keyfile)], check=True
    )
    msg = tmp_path / "msg.txt"
    msg.write_bytes(b"statement bytes")

    # OpenSSH signs, we verify
    subprocess.run(["ssh-keygen", "-Y", "sign", "-q", "-f", str(keyfile), "-n", NS, str(msg)], check=True)
    ours_raw = sshsig.verify(msg.read_bytes(), (tmp_path / "msg.txt.sig").read_text(), NS)
    assert sshsig.format_public_key(ours_raw).split()[:2] == (tmp_path / "id_ed25519.pub").read_text().split()[:2]

    # We sign, OpenSSH verifies
    key = sshsig.load_private_key(keyfile)
    (tmp_path / "ours.sig").write_text(sshsig.sign(msg.read_bytes(), key, NS))
    with msg.open("rb") as stdin:
        check = subprocess.run(
            ["ssh-keygen", "-Y", "check-novalidate", "-n", NS, "-s", str(tmp_path / "ours.sig")],
            stdin=stdin,
            capture_output=True,
            text=True,
            check=False,
        )
    assert check.returncode == 0, check.stderr
    fp = subprocess.run(
        ["ssh-keygen", "-lf", str(tmp_path / "id_ed25519.pub")], capture_output=True, text=True, check=True
    ).stdout
    assert sshsig.fingerprint(ours_raw) in fp
