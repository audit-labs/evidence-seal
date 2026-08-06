"""Tests for RFC 3161 timestamping (skipped if asn1crypto is absent).

These build tokens locally (acting as a TSA) so the whole flow is exercised
offline — no network and no real Time-Stamp Authority.
"""

from datetime import datetime, timezone

import pytest

pytest.importorskip("asn1crypto")

from asn1crypto import algos, cms, core, tsp

from evidence_seal.manifest import build_manifest, compute_id
from evidence_seal.timestamp import (
    apply_timestamp,
    build_request,
    parse_token,
    verify_timestamp,
)


def issue_token(imprint_hex: str, gen_time=None, as_response=True) -> bytes:
    """Mint a timestamp token over *imprint_hex*, as a local TSA would."""
    gen_time = gen_time or datetime(2026, 8, 6, 9, 0, tzinfo=timezone.utc)
    tst = tsp.TSTInfo(
        {
            "version": "v1",
            "policy": "1.2.3.4.5",
            "message_imprint": tsp.MessageImprint(
                {
                    "hash_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
                    "hashed_message": bytes.fromhex(imprint_hex),
                }
            ),
            "serial_number": 7,
            "gen_time": gen_time,
        }
    )
    token = cms.ContentInfo(
        {
            "content_type": "signed_data",
            "content": cms.SignedData(
                {
                    "version": "v3",
                    "digest_algorithms": [],
                    "encap_content_info": cms.EncapsulatedContentInfo(
                        {"content_type": "tst_info", "content": core.ParsableOctetString(tst.dump())}
                    ),
                    "signer_infos": [],
                }
            ),
        }
    )
    if not as_response:
        return token.dump()
    return tsp.TimeStampResp(
        {"status": {"status": "granted"}, "time_stamp_token": token}
    ).dump()


@pytest.fixture
def manifest(tmp_path):
    d = tmp_path / "pkg"
    d.mkdir()
    (d / "a.csv").write_text("x\n", encoding="utf-8")
    return build_manifest(d)


def test_build_request_carries_the_id(manifest):
    der = build_request(manifest["id"])
    req = tsp.TimeStampReq.load(der)
    assert req["message_imprint"]["hashed_message"].native.hex() == manifest["id"]
    assert req["message_imprint"]["hash_algorithm"]["algorithm"].native == "sha256"


def test_parse_token_fields(manifest):
    fields = parse_token(issue_token(manifest["id"]))
    assert fields["imprint"] == manifest["id"]
    assert fields["imprint_algorithm"] == "sha256"
    assert fields["gen_time"] == "2026-08-06T09:00:00Z"
    assert fields["serial_number"] == "7"


def test_apply_and_verify_roundtrip(manifest):
    stamped = apply_timestamp(manifest, issue_token(manifest["id"]))
    assert stamped["timestamp"]["gen_time"] == "2026-08-06T09:00:00Z"
    ok, message = verify_timestamp(stamped)
    assert ok
    assert "2026-08-06T09:00:00Z" in message


def test_apply_accepts_bare_token(manifest):
    stamped = apply_timestamp(manifest, issue_token(manifest["id"], as_response=False))
    assert verify_timestamp(stamped)[0]


def test_apply_refuses_token_for_other_id(manifest):
    wrong = "0" * 64
    with pytest.raises(ValueError, match="does not timestamp this manifest"):
        apply_timestamp(manifest, issue_token(wrong))


def test_timestamp_does_not_change_manifest_id(manifest):
    before = manifest["id"]
    stamped = apply_timestamp(manifest, issue_token(manifest["id"]))
    # The timestamp block is excluded from the id, so the id is unchanged.
    assert compute_id(stamped) == before


def test_verify_fails_if_id_changed_after_stamping(manifest):
    stamped = apply_timestamp(manifest, issue_token(manifest["id"]))
    # Simulate a re-seal after tampering: the id moves, orphaning the timestamp.
    stamped["id"] = "1" * 64
    ok, message = verify_timestamp(stamped)
    assert not ok
    assert "does not match the manifest id" in message


def test_verify_unstamped_manifest(manifest):
    ok, message = verify_timestamp(manifest)
    assert not ok
    assert "not timestamped" in message
