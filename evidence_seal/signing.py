"""Optional ed25519 signing of manifests.

Signing adds attribution — *who* sealed the evidence — on top of the integrity
the hashes already provide. It requires the ``cryptography`` package (install
``evidence-seal[sign]``); the core seal/verify path never imports this module.

The signature covers the manifest's canonical bytes (the same bytes its id is
derived from), so a valid signature vouches for every file hash and all
metadata at once.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .manifest import canonical_bytes


def _require_crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover - exercised via a clear message
        raise RuntimeError(
            "signing requires the 'cryptography' package — install evidence-seal[sign]"
        ) from exc
    return ed25519


def generate_keypair(private_path: str | Path, public_path: str | Path) -> None:
    """Write a new ed25519 keypair as PEM files (private key is unencrypted)."""
    ed25519 = _require_crypto()
    from cryptography.hazmat.primitives import serialization

    private = ed25519.Ed25519PrivateKey.generate()
    Path(private_path).write_bytes(
        private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    Path(public_path).write_bytes(
        private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def _public_hex(public_key) -> str:
    from cryptography.hazmat.primitives import serialization

    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw.hex()


def sign_manifest(manifest: dict, private_key_path: str | Path) -> dict:
    """Return a copy of *manifest* with a ``signature`` block attached."""
    _require_crypto()
    from cryptography.hazmat.primitives import serialization

    private = serialization.load_pem_private_key(
        Path(private_key_path).read_bytes(), password=None
    )
    signature = private.sign(canonical_bytes(manifest))
    signed = dict(manifest)
    signed["signature"] = {
        "algorithm": "ed25519",
        "public_key": _public_hex(private.public_key()),
        "value": signature.hex(),
        "signed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return signed


def verify_signature(manifest: dict, expected_public_key: str | None = None) -> tuple[bool, str]:
    """Verify a manifest's signature.

    Returns ``(ok, message)``. If *expected_public_key* (hex) is given, the
    signer's key must also match it — otherwise a valid signature by *any* key
    would pass, which proves integrity but not identity.
    """
    ed25519 = _require_crypto()

    block = manifest.get("signature")
    if not block:
        return False, "manifest is not signed"
    if block.get("algorithm") != "ed25519":
        return False, f"unsupported signature algorithm: {block.get('algorithm')}"

    signer_key = block.get("public_key", "")
    if expected_public_key and signer_key != expected_public_key:
        return False, "signer key does not match the expected public key"

    try:
        public = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer_key))
        public.verify(bytes.fromhex(block["value"]), canonical_bytes(manifest))
    except Exception as exc:
        return False, f"signature is invalid: {exc}"
    return True, f"valid ed25519 signature by {signer_key[:16]}…"


def load_public_hex(public_key_path: str | Path) -> str:
    """Load a PEM public key and return its raw hex form (for --pubkey checks)."""
    _require_crypto()
    from cryptography.hazmat.primitives import serialization

    public = serialization.load_pem_public_key(Path(public_key_path).read_bytes())
    return _public_hex(public)
