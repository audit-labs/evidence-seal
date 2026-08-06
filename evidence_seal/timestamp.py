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


def verify_timestamp(manifest: dict) -> tuple[bool, str]:
    """Verify a manifest's embedded timestamp binds to its id.

    Returns ``(ok, message)``. This checks that the stored token timestamps the
    current manifest id; verifying the TSA's own signature and certificate chain
    is a separate, out-of-band step (see the README threat model).
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
    return True, f"timestamped at {fields['gen_time']}{tsa}"


def load_der(path: str | Path) -> bytes:
    """Read a DER file (a ``.tsq`` request or ``.tsr`` response)."""
    return Path(path).read_bytes()
