"""SSH signatures (OpenSSH ``PROTOCOL.sshsig``) with Ed25519 keys.

Signatures are interchangeable with ``ssh-keygen -Y sign`` / ``-Y verify``, so
keys held in an SSH agent or on a hardware token can produce them and anyone
with OpenSSH can check them. The namespace binds a signature to one purpose:
a signature made for one namespace never verifies under another.

Requires the ``cryptography`` package (``evidence-seal[sign]``).
"""

from __future__ import annotations

import base64
import hashlib
import struct
from pathlib import Path

MAGIC = b"SSHSIG"
VERSION = 1
KEY_TYPE = b"ssh-ed25519"
_ARMOR_BEGIN = "-----BEGIN SSH SIGNATURE-----"
_ARMOR_END = "-----END SSH SIGNATURE-----"
_HASHES = {b"sha512": hashlib.sha512, b"sha256": hashlib.sha256}


class SignatureError(ValueError):
    """The signature is malformed, made for another namespace, or does not verify."""


def _ed25519():
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover - exercised via a clear message
        raise RuntimeError(
            "SSH signatures require the 'cryptography' package — install evidence-seal[sign]"
        ) from exc
    return ed25519


def _string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _read_string(buf: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(buf):
        raise SignatureError("truncated signature")
    (length,) = struct.unpack(">I", buf[offset : offset + 4])
    end = offset + 4 + length
    if end > len(buf):
        raise SignatureError("truncated signature")
    return buf[offset + 4 : end], end


def public_key_blob(raw_public: bytes) -> bytes:
    return _string(KEY_TYPE) + _string(raw_public)


def format_public_key(raw_public: bytes, comment: str = "") -> str:
    """OpenSSH public key line: ``ssh-ed25519 <base64> [comment]``."""
    line = f"ssh-ed25519 {base64.b64encode(public_key_blob(raw_public)).decode('ascii')}"
    return f"{line} {comment}".rstrip()


def parse_public_key(line: str) -> bytes:
    """Return the raw 32-byte Ed25519 key from an OpenSSH public key line."""
    parts = str(line or "").split()
    if len(parts) < 2 or parts[0] != KEY_TYPE.decode():
        raise SignatureError("expected an ssh-ed25519 public key")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except ValueError as exc:
        raise SignatureError("public key is not valid base64") from exc
    key_type, offset = _read_string(blob, 0)
    raw, offset = _read_string(blob, offset)
    if key_type != KEY_TYPE or len(raw) != 32 or offset != len(blob):
        raise SignatureError("malformed ssh-ed25519 public key")
    return raw


def fingerprint(raw_public: bytes) -> str:
    """OpenSSH SHA256 fingerprint, as printed by ``ssh-keygen -lf``."""
    digest = hashlib.sha256(public_key_blob(raw_public)).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _signed_data(namespace: str, message: bytes, hash_name: bytes = b"sha512") -> bytes:
    return (
        MAGIC
        + _string(namespace.encode("utf-8"))
        + _string(b"")
        + _string(hash_name)
        + _string(_HASHES[hash_name](message).digest())
    )


def load_private_key(path: str | Path, passphrase: bytes | None = None):
    """Load an Ed25519 private key from PEM (PKCS#8, optionally encrypted) or OpenSSH format."""
    ed25519 = _ed25519()
    from cryptography.hazmat.primitives import serialization

    data = Path(path).read_bytes()
    if b"OPENSSH PRIVATE KEY" in data:
        key = serialization.load_ssh_private_key(data, password=passphrase)
    else:
        key = serialization.load_pem_private_key(data, password=passphrase)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise SignatureError("only Ed25519 keys are supported")
    return key


def raw_public_key(private_key) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )


def sign(message: bytes, private_key, namespace: str) -> str:
    """Return an armored SSH signature of *message* under *namespace*."""
    _ed25519()
    signature = private_key.sign(_signed_data(namespace, message))
    blob = (
        MAGIC
        + struct.pack(">I", VERSION)
        + _string(public_key_blob(raw_public_key(private_key)))
        + _string(namespace.encode("utf-8"))
        + _string(b"")
        + _string(b"sha512")
        + _string(_string(KEY_TYPE) + _string(signature))
    )
    encoded = base64.b64encode(blob).decode("ascii")
    lines = [encoded[i : i + 70] for i in range(0, len(encoded), 70)]
    return "\n".join([_ARMOR_BEGIN, *lines, _ARMOR_END]) + "\n"


def verify(message: bytes, armored: str, namespace: str) -> bytes:
    """Verify an armored SSH signature; return the signer's raw public key.

    Raises :class:`SignatureError` if the signature is malformed, was made for
    another namespace, or does not match *message*. Checking that the signer is
    someone you trust is the caller's job.
    """
    ed25519 = _ed25519()
    text = str(armored or "").strip()
    if not (text.startswith(_ARMOR_BEGIN) and text.endswith(_ARMOR_END)):
        raise SignatureError("not an armored SSH signature")
    body = "".join(text[len(_ARMOR_BEGIN) : -len(_ARMOR_END)].split())
    try:
        blob = base64.b64decode(body, validate=True)
    except ValueError as exc:
        raise SignatureError("signature is not valid base64") from exc
    if not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + 4:
        raise SignatureError("not an SSHSIG signature")
    (version,) = struct.unpack(">I", blob[len(MAGIC) : len(MAGIC) + 4])
    if version != VERSION:
        raise SignatureError(f"unsupported SSHSIG version {version}")
    offset = len(MAGIC) + 4
    key_blob, offset = _read_string(blob, offset)
    sig_namespace, offset = _read_string(blob, offset)
    _reserved, offset = _read_string(blob, offset)
    hash_name, offset = _read_string(blob, offset)
    sig_blob, offset = _read_string(blob, offset)
    if offset != len(blob):
        raise SignatureError("trailing data after signature")
    if sig_namespace.decode("utf-8", "replace") != namespace:
        raise SignatureError(
            f"signature namespace {sig_namespace.decode('utf-8', 'replace')!r} is not {namespace!r}"
        )
    if hash_name not in _HASHES:
        raise SignatureError(f"unsupported hash {hash_name!r}")
    key_type, k_off = _read_string(key_blob, 0)
    raw_public, k_off = _read_string(key_blob, k_off)
    sig_type, s_off = _read_string(sig_blob, 0)
    raw_sig, s_off = _read_string(sig_blob, s_off)
    if key_type != KEY_TYPE or sig_type != KEY_TYPE or len(raw_public) != 32:
        raise SignatureError("only ssh-ed25519 signatures are supported")
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(raw_public).verify(
            raw_sig, _signed_data(namespace, message, hash_name)
        )
    except Exception as exc:
        raise SignatureError("signature does not match the signed data") from exc
    return raw_public
