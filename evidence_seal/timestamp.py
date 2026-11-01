"""Optional RFC 3161 trusted timestamping of manifests.

A signature proves *who* sealed the evidence; a timestamp proves the seal
existed *by* a certain time — attested by an independent Time-Stamp Authority
(TSA), not by the sealer's own clock. The TSA timestamps the manifest's ``id``
(itself the hash of every file and all metadata), so one token vouches for the
whole package at a point in time.

This module builds RFC 3161 requests, submits them to a TSA, and binds the
returned token into the manifest. It needs the ``asn1crypto`` package (install
``evidence-seal[timestamp]``); the core seal/verify path never imports it.

The bound token is stored under a ``timestamp`` key, which — like ``signature``
— is excluded from the manifest id, so timestamping never invalidates the id or
an existing signature.
"""

from __future__ import annotations

import base64
import secrets
import urllib.parse
import urllib.request
from datetime import timezone
from pathlib import Path

_TSA_CONTENT_TYPE = "application/timestamp-query"
_TSA_ACCEPT = "application/timestamp-reply"


def _require_asn1():
    try:
        from asn1crypto import algos, cms, core, tsp
    except ImportError as exc:  # pragma: no cover - exercised via a clear message
        raise RuntimeError(
            "timestamping requires the 'asn1crypto' package — "
            "install evidence-seal[timestamp]"
        ) from exc
    return algos, cms, core, tsp


def _require_crypto():
    try:
        import cryptography  # noqa: F401
    except ImportError as exc:  # pragma: no cover - exercised via a clear message
        raise RuntimeError(
            "verifying a TSA signature requires the 'cryptography' package — "
            "install evidence-seal[sign,timestamp]"
        ) from exc


def build_request(manifest_id_hex: str, cert_req: bool = True) -> bytes:
    """Return a DER-encoded RFC 3161 TimeStampReq over a manifest id.

    The message imprint is the manifest id (a SHA-256 digest) carried directly
    as the hashed message, so the TSA timestamps exactly what the id commits to.
    """
    algos, _cms, core, tsp = _require_asn1()
    request = tsp.TimeStampReq(
        {
            "version": 1,
            "message_imprint": tsp.MessageImprint(
                {
                    "hash_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
                    "hashed_message": bytes.fromhex(manifest_id_hex),
                }
            ),
            "nonce": core.Integer(secrets.randbits(64)),
            "cert_req": cert_req,
        }
    )
    return request.dump()


def submit(request_der: bytes, tsa_url: str, timeout: float = 30.0) -> bytes:
    """POST a TimeStampReq to a TSA and return the raw TimeStampResp bytes.

    Network call — the caller is responsible for choosing a trusted TSA URL.
    """
    scheme = urllib.parse.urlsplit(tsa_url).scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"TSA URL must use http or https: {tsa_url}")
    req = urllib.request.Request(
        tsa_url,
        data=request_der,
        headers={"Content-Type": _TSA_CONTENT_TYPE, "Accept": _TSA_ACCEPT},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read()


def _extract(token_or_response_der: bytes):
    """Return ``(token_contentinfo, tst_info)`` from a token or a TimeStampResp.

    Accepts either a bare RFC 3161 token (a CMS ContentInfo) or a full
    TimeStampResp (what a TSA returns and a ``.tsr`` file holds).
    """
    _algos, cms, _core, tsp = _require_asn1()

    def _tst_of(content_info):
        return content_info["content"]["encap_content_info"]["content"].parsed

    # Try a full response first; fall back to a bare token.
    try:
        response = tsp.TimeStampResp.load(token_or_response_der)
        status = response["status"]["status"].native
        token = response["time_stamp_token"]
        tst = _tst_of(token)  # forces a parse; raises if this was not a response
    except Exception:
        token = cms.ContentInfo.load(token_or_response_der)
        return token, _tst_of(token), None
    return token, tst, status


def parse_token(token_or_response_der: bytes) -> dict:
    """Extract the human-facing fields from a timestamp token."""
    _token, tst, _status = _extract(token_or_response_der)
    gen_time = tst["gen_time"].native.astimezone(timezone.utc)
    tsa = None
    if tst["tsa"].native is not None:
        tsa = str(tst["tsa"].native)
    return {
        "imprint": tst["message_imprint"]["hashed_message"].native.hex(),
        "imprint_algorithm": tst["message_imprint"]["hash_algorithm"]["algorithm"].native,
        "gen_time": gen_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "serial_number": str(tst["serial_number"].native),
        "tsa": tsa,
    }


def apply_timestamp(manifest: dict, token_or_response_der: bytes) -> dict:
    """Bind a TSA token into *manifest* after checking it timestamps its id.

    Raises ``ValueError`` if the token's message imprint does not equal the
    manifest id — a token for anything else must never be attached.
    """
    token, _tst, _status = _extract(token_or_response_der)
    fields = parse_token(token_or_response_der)

    if fields["imprint_algorithm"] != "sha256" or fields["imprint"] != manifest.get("id"):
        raise ValueError("token does not timestamp this manifest's id")

    stamped = dict(manifest)
    stamped["timestamp"] = {
        "format": "rfc3161",
        "imprint_algorithm": fields["imprint_algorithm"],
        "imprint": fields["imprint"],
        "gen_time": fields["gen_time"],
        "serial_number": fields["serial_number"],
        "tsa": fields["tsa"],
        "token": base64.b64encode(token.dump()).decode(),
    }
    return stamped


def verify_timestamp(manifest: dict, tsa_cert: bytes | None = None) -> tuple[bool, str]:
    """Verify a manifest's embedded timestamp.

    Returns ``(ok, message)``. Always checks that the stored token timestamps the
    current manifest id. When *tsa_cert* (PEM or DER bytes) is given, the token's
    RFC 3161 CMS signature is also verified against that certificate — proving
    the timestamp really was issued by that authority.
    """
    block = manifest.get("timestamp")
    if not block:
        return False, "manifest is not timestamped"
    if block.get("format") != "rfc3161":
        return False, f"unsupported timestamp format: {block.get('format')}"

    try:
        token_der = base64.b64decode(block["token"])
        fields = parse_token(token_der)
    except Exception as exc:
        return False, f"timestamp token is unreadable: {exc}"

    if fields["imprint_algorithm"] != "sha256" or fields["imprint"] != manifest.get("id"):
        return False, "timestamp does not match the manifest id"

    tsa = f" by {fields['tsa']}" if fields["tsa"] else ""
    bound = f"timestamped at {fields['gen_time']}{tsa}"

    if tsa_cert is None:
        return True, bound

    sig_ok, sig_message = verify_token_signature(token_der, tsa_cert)
    return sig_ok, f"{bound}; {sig_message}"


# --------------------------------------------------------------------------- #
# Full RFC 3161 CMS signature verification
# --------------------------------------------------------------------------- #

# asn1crypto hash names -> cryptography hash classes for the algorithms a TSA
# realistically signs with.
_HASHES = {
    "sha1": "SHA1",
    "sha224": "SHA224",
    "sha256": "SHA256",
    "sha384": "SHA384",
    "sha512": "SHA512",
}


def _load_certificate(cert_bytes: bytes):
    from cryptography import x509

    try:
        return x509.load_pem_x509_certificate(cert_bytes)
    except ValueError:
        return x509.load_der_x509_certificate(cert_bytes)


def _hash_instance(name: str):
    from cryptography.hazmat.primitives import hashes

    if name not in _HASHES:
        raise ValueError(f"unsupported digest algorithm: {name}")
    return getattr(hashes, _HASHES[name])()


def _verify_raw(public_key, signature: bytes, data: bytes, sig_algo: str, hash_name: str) -> None:
    """Verify *signature* over *data*, raising on any failure."""
    from cryptography.hazmat.primitives.asymmetric import ec, padding

    if sig_algo == "rsassa_pkcs1v15":
        public_key.verify(signature, data, padding.PKCS1v15(), _hash_instance(hash_name))
    elif sig_algo == "rsassa_pss":
        digest = _hash_instance(hash_name)
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(digest), salt_length=padding.PSS.DIGEST_LENGTH),
            digest,
        )
    elif sig_algo == "ecdsa":
        public_key.verify(signature, data, ec.ECDSA(_hash_instance(hash_name)))
    elif sig_algo in ("ed25519", "ed448"):
        public_key.verify(signature, data)
    else:
        raise ValueError(f"unsupported signature algorithm: {sig_algo}")


def _signer_matches_cert(signer_info, cert) -> bool:
    """True if the SignerInfo identifies the supplied certificate."""
    sid = signer_info["sid"]
    if sid.name == "issuer_and_serial_number":
        return sid.chosen["serial_number"].native == cert.serial_number
    # subject_key_identifier: compare against the cert's SKI extension.
    from cryptography import x509

    try:
        ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    except x509.ExtensionNotFound:
        return False
    return sid.chosen.native == ski.digest


def _has_timestamping_eku(cert) -> bool:
    from cryptography import x509
    from cryptography.x509.oid import ExtendedKeyUsageOID

    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return False
    return ExtendedKeyUsageOID.TIME_STAMPING in eku


def _signed_attr(signed_attrs, attr_type):
    for attr in signed_attrs:
        if attr["type"].native == attr_type:
            return attr["values"][0].native
    return None


def verify_token_signature(token_or_response_der: bytes, cert_bytes: bytes) -> tuple[bool, str]:
    """Verify a token's CMS signature against a TSA certificate.

    Checks, in order: the certificate carries the timeStamping extended key
    usage; it identifies the token's signer; ``gen_time`` falls within its
    validity window; the signed message digest matches the timestamped content;
    and the signature verifies. Returns ``(ok, message)``.

    This authenticates the token against the certificate you supply. Establishing
    that the certificate itself is trusted (chain to a known root) is left to the
    caller — supply a TSA certificate you already trust.
    """
    import hashlib

    _require_asn1()
    _require_crypto()

    try:
        token, tst, _status = _extract(token_or_response_der)
        signed_data = token["content"]
        signer_info = signed_data["signer_infos"][0]
    except Exception as exc:
        return False, f"TSA signature: token is unreadable ({exc})"

    try:
        cert = _load_certificate(cert_bytes)
    except ValueError as exc:
        return False, f"TSA signature: cannot load certificate ({exc})"

    if not _has_timestamping_eku(cert):
        return False, "TSA signature: certificate lacks the timeStamping extended key usage"
    if not _signer_matches_cert(signer_info, cert):
        return False, "TSA signature: certificate does not match the token's signer"

    gen_time = tst["gen_time"].native.astimezone(timezone.utc)
    if not (cert.not_valid_before_utc <= gen_time <= cert.not_valid_after_utc):
        return False, "TSA signature: gen_time is outside the certificate validity window"

    econtent = signed_data["encap_content_info"]["content"].parsed.dump()
    digest_name = signer_info["digest_algorithm"]["algorithm"].native
    signed_attrs = signer_info["signed_attrs"]

    if signed_attrs.native is not None:
        recorded = _signed_attr(signed_attrs, "message_digest")
        if recorded is None or recorded != hashlib.new(digest_name, econtent).digest():
            return False, "TSA signature: signed message digest does not match the token content"
        signed_bytes = signed_attrs.untag().dump()
    else:
        signed_bytes = econtent

    sig_algo = signer_info["signature_algorithm"].signature_algo
    # For rsassa_pkcs1v15 the OID carries no hash, and asn1crypto raises rather
    # than returning None — fall back to the SignerInfo digest algorithm.
    try:
        hash_name = signer_info["signature_algorithm"].hash_algo or digest_name
    except ValueError:
        hash_name = digest_name
    try:
        _verify_raw(
            cert.public_key(), signer_info["signature"].native, signed_bytes, sig_algo, hash_name
        )
    except ValueError as exc:
        return False, f"TSA signature: {exc}"
    except Exception as exc:
        return False, f"TSA signature is INVALID ({type(exc).__name__})"

    return True, f"TSA signature valid ({cert.subject.rfc4514_string()})"


def load_der(path: str | Path) -> bytes:
    """Read a DER file (a ``.tsq`` request or ``.tsr`` response)."""
    return Path(path).read_bytes()
