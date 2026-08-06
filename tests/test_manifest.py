"""Tests for building, verifying, and chaining manifests."""

import pytest

from evidence_seal.manifest import (
    build_manifest,
    compute_id,
    verify_chain,
    verify_manifest,
)


@pytest.fixture
def pkg(tmp_path):
    d = tmp_path / "aws_audit_acme_2026-01-01"
    d.mkdir()
    (d / "iam.csv").write_text("user,mfa\nalice,true\n", encoding="utf-8")
    (d / "summary.txt").write_text("ok\n", encoding="utf-8")
    return d


def test_build_manifest_shape(pkg):
    m = build_manifest(pkg, metadata={"engagement": "ACME"})
    assert m["subject"] == "aws_audit_acme_2026-01-01"
    assert m["file_count"] == 2
    assert m["metadata"] == {"engagement": "ACME"}
    assert [f["path"] for f in m["files"]] == ["iam.csv", "summary.txt"]
    assert m["id"] == compute_id(m)


def test_verify_clean(pkg):
    m = build_manifest(pkg)
    result = verify_manifest(pkg, m)
    assert result.intact
    assert result.checked == 2


def test_verify_detects_modification(pkg):
    m = build_manifest(pkg)
    (pkg / "iam.csv").write_text("user,mfa\nalice,false\n", encoding="utf-8")
    result = verify_manifest(pkg, m)
    assert not result.intact
    assert result.modified == ["iam.csv"]


def test_verify_detects_added_and_removed(pkg):
    m = build_manifest(pkg)
    (pkg / "extra.csv").write_text("new\n", encoding="utf-8")
    (pkg / "summary.txt").unlink()
    result = verify_manifest(pkg, m)
    assert result.added == ["extra.csv"]
    assert result.removed == ["summary.txt"]
    assert not result.intact


def test_verify_detects_manifest_tampering(pkg):
    m = build_manifest(pkg)
    # Rewrite a recorded hash but leave the (now stale) id in place.
    m["files"][0]["sha256"] = "0" * 64
    result = verify_manifest(pkg, m)
    assert not result.id_ok
    assert not result.root_ok
    assert not result.intact


def test_ignore_patterns_excluded_and_recorded(pkg):
    (pkg / "notes.tmp").write_text("scratch\n", encoding="utf-8")
    m = build_manifest(pkg, ignore=["*.tmp"])
    assert m["ignore"] == ["*.tmp"]
    assert all(not f["path"].endswith(".tmp") for f in m["files"])
    # Verify with the same ignore keeps it intact despite the tmp file present.
    assert verify_manifest(pkg, m, ignore=m["ignore"]).intact


def test_chain_links(pkg):
    m1 = build_manifest(pkg)
    (pkg / "iam.csv").write_text("user,mfa\nalice,true\nbob,true\n", encoding="utf-8")
    m2 = build_manifest(pkg, previous=m1["id"])
    assert verify_chain([m1, m2]).ok


def test_chain_detects_wrong_order(pkg):
    m1 = build_manifest(pkg)
    m2 = build_manifest(pkg, previous=m1["id"])
    result = verify_chain([m2, m1])
    assert not result.ok
    assert result.broken_at == 0


def test_chain_detects_spliced_entry(pkg):
    m1 = build_manifest(pkg)
    m2 = build_manifest(pkg, previous=m1["id"])
    m3 = build_manifest(pkg, previous=m2["id"])
    # Drop the middle manifest: m3.previous no longer matches m1.id.
    result = verify_chain([m1, m3])
    assert not result.ok
    assert result.broken_at == 1


def test_missing_directory_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        build_manifest(tmp_path / "nope")
