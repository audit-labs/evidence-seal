"""Tests for offline roster and sign-off verification."""

import json

import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.asymmetric import ed25519

from evidence_seal import signoffs, sshsig
from evidence_seal.cli import main


def _key():
    k = ed25519.Ed25519PrivateKey.generate()
    return k, sshsig.format_public_key(sshsig.raw_public_key(k))


@pytest.fixture
def folder(tmp_path):
    firm, _ = _key()
    alice, alice_pub = _key()
    alice2, alice2_pub = _key()
    bob, bob_pub = _key()
    roster = {
        "version": 1,
        "firm": "Acme CPA",
        "members": [
            {"name": "Alice", "roles": ["preparer", "reviewer"], "keys": [alice_pub, alice2_pub]},
            {"name": "Bob", "roles": ["reviewer"], "keys": [bob_pub]},
        ],
    }
    roster_bytes = json.dumps(roster, indent=2).encode()
    (tmp_path / "team.json").write_bytes(roster_bytes)
    (tmp_path / "team.json.sig").write_text(sshsig.sign(roster_bytes, firm, signoffs.ROSTER_NAMESPACE))
    keys = {"firm": firm, "alice": (alice, alice_pub), "alice2": (alice2, alice2_pub), "bob": (bob, bob_pub)}
    trusted = {sshsig.fingerprint(sshsig.raw_public_key(firm))}
    return tmp_path, keys, trusted


def _statement(item, role, signer, pub, content="c1"):
    return {
        "version": 1,
        "item": item,
        "role": role,
        "content_hash": content,
        "evidence_sha256": "e" * 64,
        "signer": signer,
        "key": pub,
        "time": "2026-07-31T12:00:00Z",
    }


def _write(folder, entries):
    (folder / "signoffs.jsonl").write_text("".join(json.dumps(e) + "\n" for e in entries))


def _signed(key, statement):
    return {"statement": statement, "signature": sshsig.sign(signoffs.canonical(statement), key, signoffs.SIGNOFF_NAMESPACE)}


def test_independent_review_is_complete(folder):
    path, keys, trusted = folder
    alice, alice_pub = keys["alice"]
    bob, bob_pub = keys["bob"]
    _write(path, [
        _signed(alice, _statement("SOC2:CC6.1", "preparer", "Alice", alice_pub)),
        _signed(bob, _statement("SOC2:CC6.1", "reviewer", "Bob", bob_pub)),
    ])
    result = signoffs.verify_folder(path, trusted)
    assert result["invalid"] == 0
    assert result["items"]["SOC2:CC6.1"]["c1"]["complete"] is True


def test_self_review_with_a_second_key_is_not_independent(folder):
    path, keys, trusted = folder
    alice, alice_pub = keys["alice"]
    alice2, alice2_pub = keys["alice2"]
    _write(path, [
        _signed(alice, _statement("X", "preparer", "Alice", alice_pub)),
        _signed(alice2, _statement("X", "reviewer", "Alice", alice2_pub)),
    ])
    result = signoffs.verify_folder(path, trusted)
    assert result["invalid"] == 0
    assert result["items"]["X"]["c1"]["complete"] is False


def test_forged_and_misattributed_statements_fail(folder):
    path, keys, trusted = folder
    alice, alice_pub = keys["alice"]
    bob, bob_pub = keys["bob"]
    outsider, outsider_pub = _key()
    forged = _signed(alice, _statement("X", "reviewer", "Alice", alice_pub))
    forged["statement"]["signer"] = "Bob"  # edited after signing
    _write(path, [
        forged,
        _signed(alice, _statement("X", "reviewer", "Bob", alice_pub)),  # Alice claiming to be Bob
        _signed(bob, _statement("X", "preparer", "Bob", bob_pub)),  # Bob lacks preparer role
        _signed(outsider, _statement("X", "reviewer", "Eve", outsider_pub)),
    ])
    result = signoffs.verify_folder(path, trusted)
    reasons = [r["reason"] for r in result["statements"]]
    assert result["invalid"] == 4
    assert "does not match" in reasons[0]
    assert "belongs to Alice" in reasons[1]
    assert "role" in reasons[2]
    assert "not in the roster" in reasons[3]


def test_tampered_or_untrusted_roster_fails(folder, capsys):
    path, _keys, trusted = folder
    roster = json.loads((path / "team.json").read_text())
    roster["members"][1]["roles"].append("preparer")
    (path / "team.json").write_text(json.dumps(roster))
    with pytest.raises(sshsig.SignatureError):
        signoffs.verify_folder(path, trusted)
    assert main(["signoffs", str(path), "--trust", next(iter(trusted))]) == 1

    other, _ = _key()
    with pytest.raises(sshsig.SignatureError, match="not a trusted firm key"):
        signoffs.verify_roster(b"{}", sshsig.sign(b"{}", other, signoffs.ROSTER_NAMESPACE), trusted)


def test_cli_reports_reviewed_items(folder, capsys):
    path, keys, trusted = folder
    alice, alice_pub = keys["alice"]
    bob, bob_pub = keys["bob"]
    _write(path, [
        _signed(alice, _statement("SOC2:CC6.1", "preparer", "Alice", alice_pub)),
        _signed(bob, _statement("SOC2:CC6.1", "reviewer", "Bob", bob_pub)),
    ])
    assert main(["signoffs", str(path), "--trust", next(iter(trusted))]) == 0
    out = capsys.readouterr().out
    assert "roster OK: Acme CPA" in out and "item SOC2:CC6.1: reviewed" in out
