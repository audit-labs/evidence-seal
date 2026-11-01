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
    submit,
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


def issue_signed_token(imprint_hex, gen_time=None, timestamping_eku=True, validity=None):
    """Mint a genuinely CMS-signed token; return ``(response_der, cert_pem)``.

    Acts as a real (self-signed) TSA so full signature verification can be
    exercised offline.
    """
    import datetime

    from asn1crypto import x509 as a1x509
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    gen_time = gen_time or datetime.datetime(2026, 8, 6, 9, 0, tzinfo=datetime.timezone.utc)
    not_before, not_after = validity or (
        datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc),
        datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc),
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TSA")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(4242)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if timestamping_eku:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True
        )
    cert = builder.sign(key, hashes.SHA256())
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    imprint = tsp.MessageImprint(
        {
            "hash_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
            "hashed_message": bytes.fromhex(imprint_hex),
        }
    )
    tst = tsp.TSTInfo(
        {
            "version": "v1",
            "policy": "1.2.3.4.5",
            "message_imprint": imprint,
            "serial_number": 7,
            "gen_time": gen_time,
        }
    )
    econtent = tst.dump()

    import hashlib

    signed_attrs = cms.CMSAttributes(
        [
            cms.CMSAttribute({"type": "content_type", "values": ["tst_info"]}),
            cms.CMSAttribute(
                {"type": "message_digest", "values": [core.OctetString(hashlib.sha256(econtent).digest())]}
            ),
        ]
    )
    signature = key.sign(signed_attrs.untag().dump(), padding.PKCS1v15(), hashes.SHA256())
    signer_info = cms.SignerInfo(
        {
            "version": "v1",
            "sid": cms.SignerIdentifier(
                {
                    "issuer_and_serial_number": cms.IssuerAndSerialNumber(
                        {"issuer": a1x509.Certificate.load(cert_der).issuer, "serial_number": 4242}
                    )
                }
            ),
            "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
            "signed_attrs": signed_attrs,
            "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": "rsassa_pkcs1v15"}),
            "signature": signature,
        }
    )
    signed_data = cms.SignedData(
        {
            "version": "v3",
            "digest_algorithms": [algos.DigestAlgorithm({"algorithm": "sha256"})],
            "encap_content_info": cms.EncapsulatedContentInfo(
                {"content_type": "tst_info", "content": core.ParsableOctetString(econtent)}
            ),
            "certificates": [a1x509.Certificate.load(cert_der)],
            "signer_infos": [signer_info],
        }
    )
    token = cms.ContentInfo({"content_type": "signed_data", "content": signed_data})
    response = tsp.TimeStampResp({"status": {"status": "granted"}, "time_stamp_token": token})
    return response.dump(), cert_pem


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
    token = issue_token(wrong)
    with pytest.raises(ValueError, match="does not timestamp this manifest"):
        apply_timestamp(manifest, token)


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


def test_submit_rejects_non_http_url(manifest, tmp_path):
    target = tmp_path / "tsa.tsr"
    target.write_bytes(b"")
    with pytest.raises(ValueError, match="http or https"):
        submit(build_request(manifest["id"]), target.as_uri())


# --- full CMS signature verification (needs cryptography) ---


def test_full_signature_verifies(manifest):
    pytest.importorskip("cryptography")
    from evidence_seal.timestamp import verify_token_signature

    token, cert_pem = issue_signed_token(manifest["id"])
    ok, message = verify_token_signature(token, cert_pem)
    assert ok
    assert "valid" in message
    assert "Test TSA" in message


def test_full_signature_via_verify_timestamp(manifest):
    pytest.importorskip("cryptography")
    token, cert_pem = issue_signed_token(manifest["id"])
    stamped = apply_timestamp(manifest, token)
    ok, message = verify_timestamp(stamped, tsa_cert=cert_pem)
    assert ok
    assert "TSA signature valid" in message


def test_full_signature_wrong_cert_rejected(manifest):
    pytest.importorskip("cryptography")
    from evidence_seal.timestamp import verify_token_signature

    token, _cert = issue_signed_token(manifest["id"])
    _other_token, other_cert = issue_signed_token(manifest["id"])
    # A different cert (different key, but same serial in our helper) must fail
    # either the signer match or the cryptographic check.
    ok, message = verify_token_signature(token, other_cert)
    assert not ok
    assert "TSA signature" in message


def test_full_signature_missing_eku_rejected(manifest):
    pytest.importorskip("cryptography")
    from evidence_seal.timestamp import verify_token_signature

    token, cert_pem = issue_signed_token(manifest["id"], timestamping_eku=False)
    ok, message = verify_token_signature(token, cert_pem)
    assert not ok
    assert "timeStamping" in message


def test_full_signature_gen_time_outside_validity_rejected(manifest):
    import datetime

    pytest.importorskip("cryptography")
    from evidence_seal.timestamp import verify_token_signature

    # gen_time in 2026 but the cert is only valid in 2020.
    token, cert_pem = issue_signed_token(
        manifest["id"],
        validity=(
            datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc),
            datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc),
        ),
    )
    ok, message = verify_token_signature(token, cert_pem)
    assert not ok
    assert "validity window" in message


def test_full_signature_tampered_content_rejected(manifest):
    pytest.importorskip("cryptography")
    from evidence_seal.timestamp import verify_token_signature

    # A token whose imprint is for a different id: the signature is valid over
    # its own content, but apply_timestamp would refuse it, and here we confirm
    # the signature itself is bound to the (wrong) content it was issued for.
    token, cert_pem = issue_signed_token("a" * 64)
    ok, _message = verify_token_signature(token, cert_pem)
    assert ok  # signature is valid for its own content...
    # ...but it does not bind to this manifest, which apply enforces.
    with pytest.raises(ValueError, match="does not timestamp"):
        apply_timestamp(manifest, token)
