"""Tests for file hashing and the Merkle root."""

from evidence_seal.hashing import hash_bytes, hash_file, merkle_root


def test_hash_file_matches_known_sha256(tmp_path):
    f = tmp_path / "x.txt"
    f.write_bytes(b"hello")
    # Known SHA-256 of "hello".
    assert hash_file(f) == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    assert hash_bytes(b"hello") == hash_file(f)


def test_merkle_root_is_order_independent():
    a = {"a": "1", "b": "2", "c": "3"}
    b = {"c": "3", "a": "1", "b": "2"}
    assert merkle_root(a) == merkle_root(b)


def test_merkle_root_changes_on_content():
    base = {"a": "1", "b": "2"}
    changed = {"a": "1", "b": "changed"}
    assert merkle_root(base) != merkle_root(changed)


def test_merkle_root_changes_on_rename():
    # Same content hash, different path -> different root (path is bound in).
    assert merkle_root({"a": "1"}) != merkle_root({"b": "1"})


def test_empty_root_is_defined_and_distinct():
    assert merkle_root({}) == hash_bytes(b"empty")
    assert merkle_root({}) != merkle_root({"a": "1"})


def test_odd_number_of_leaves():
    # Three leaves exercises the duplicate-last branch; just needs to be stable.
    entries = {"a": "1", "b": "2", "c": "3"}
    assert merkle_root(entries) == merkle_root(dict(entries))
