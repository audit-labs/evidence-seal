"""Command-line interface for evidence-seal."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .manifest import (
    build_manifest,
    load_manifest,
    verify_chain,
    verify_manifest,
    write_manifest,
)

# Exit codes: 0 = intact/valid, 1 = tamper/verification failure, 2 = usage error.
OK, FAILED, USAGE = 0, 1, 2


def _default_manifest_path(directory: Path) -> Path:
    return directory.parent / f"{directory.name}.manifest.json"


def _manifest_exclude(directory: Path, manifest_path: Path) -> set[str]:
    """If the manifest lives inside the sealed dir, it must not seal itself."""
    try:
        return {manifest_path.resolve().relative_to(directory.resolve()).as_posix()}
    except ValueError:
        return set()


def _parse_meta(pairs: list[str]) -> dict:
    meta = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise ValueError(f"metadata must be key=value, got {pair!r}")
        key, value = pair.split("=", 1)
        meta[key.strip()] = value.strip()
    return meta


def _cmd_seal(args) -> int:
    directory = Path(args.directory)
    manifest_path = Path(args.out) if args.out else _default_manifest_path(directory)

    previous = None
    if args.prev:
        previous = load_manifest(args.prev).get("id")

    try:
        manifest = build_manifest(
            directory,
            metadata=_parse_meta(args.meta),
            previous=previous,
            ignore=args.ignore,
            exclude=_manifest_exclude(directory, manifest_path),
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return USAGE

    if args.sign:
        from .signing import sign_manifest

        try:
            manifest = sign_manifest(manifest, args.sign)
        except (RuntimeError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return USAGE

    write_manifest(manifest, manifest_path)
    signed = " (signed)" if "signature" in manifest else ""
    print(f"sealed {manifest['file_count']} files{signed}", file=sys.stderr)
    print(f"  root {manifest['root']}", file=sys.stderr)
    print(f"  id   {manifest['id']}", file=sys.stderr)
    print(f"  -> {manifest_path}", file=sys.stderr)
    return OK


def _cmd_verify(args) -> int:
    directory = Path(args.directory)
    manifest_path = Path(args.manifest) if args.manifest else _default_manifest_path(directory)
    try:
        manifest = load_manifest(manifest_path)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: cannot read manifest: {exc}", file=sys.stderr)
        return USAGE

    result = verify_manifest(
        directory,
        manifest,
        ignore=manifest.get("ignore"),
        exclude=_manifest_exclude(directory, manifest_path),
    )

    for path in result.modified:
        print(f"  MODIFIED  {path}")
    for path in result.added:
        print(f"  ADDED     {path}")
    for path in result.removed:
        print(f"  REMOVED   {path}")
    if not result.id_ok:
        print("  MANIFEST  id does not re-derive — the manifest itself was altered")
    if not result.root_ok:
        print("  MANIFEST  Merkle root does not match the file list")

    status = OK
    if not result.intact:
        status = FAILED

    # Verify a signature when present, or when the caller supplied a key to trust.
    if (manifest.get("signature") or args.pubkey) and not _verify_sig_cli(manifest, args.pubkey):
        status = FAILED

    # Verify an embedded timestamp when present.
    if manifest.get("timestamp"):
        from .timestamp import verify_timestamp

        cert = Path(args.tsa_cert).read_bytes() if args.tsa_cert else None
        ts_ok, ts_message = verify_timestamp(manifest, tsa_cert=cert)
        print(f"  timestamp {'OK' if ts_ok else 'FAIL'}: {ts_message}")
        if not ts_ok:
            status = FAILED

    if status == OK:
        print(f"intact — {result.checked} files match the seal")
    else:
        print("TAMPERED — the directory does not match its seal", file=sys.stderr)
    return status


def _verify_sig_cli(manifest: dict, pubkey_path: str | None) -> bool:
    from .signing import load_public_hex, verify_signature

    expected = load_public_hex(pubkey_path) if pubkey_path else None
    ok, message = verify_signature(manifest, expected)
    print(f"  signature {'OK' if ok else 'FAIL'}: {message}")
    return ok


def _cmd_chain(args) -> int:
    try:
        manifests = [load_manifest(p) for p in args.manifests]
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: cannot read manifest: {exc}", file=sys.stderr)
        return USAGE

    result = verify_chain(manifests)
    if result.ok:
        print(f"chain intact — {result.length} seals link correctly")
        return OK
    where = "" if result.broken_at is None else f" at position {result.broken_at}"
    print(f"CHAIN BROKEN{where}: {result.reason}", file=sys.stderr)
    return FAILED


def _cmd_keygen(args) -> int:
    from .signing import generate_keypair

    try:
        generate_keypair(args.private, args.public)
    except (RuntimeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return USAGE
    print(f"wrote private key {args.private}", file=sys.stderr)
    print(f"wrote public key  {args.public}", file=sys.stderr)
    return OK


def _cmd_sign(args) -> int:
    from .signing import sign_manifest

    try:
        manifest = load_manifest(args.manifest)
        signed = sign_manifest(manifest, args.key)
    except (RuntimeError, FileNotFoundError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return USAGE
    write_manifest(signed, args.out or args.manifest)
    print(f"signed {args.out or args.manifest}", file=sys.stderr)
    return OK


def _cmd_ts_request(args) -> int:
    from .timestamp import build_request

    try:
        manifest = load_manifest(args.manifest)
        request = build_request(manifest["id"])
    except (RuntimeError, FileNotFoundError, ValueError, KeyError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return USAGE
    out = args.out or f"{args.manifest}.tsq"
    Path(out).write_bytes(request)
    print(f"wrote timestamp request for id {manifest['id'][:16]}… -> {out}", file=sys.stderr)
    print("submit it to a TSA, e.g.:", file=sys.stderr)
    print(
        f"  curl -sS -H 'Content-Type: application/timestamp-query' "
        f"--data-binary @{out} <TSA_URL> -o {out.removesuffix('.tsq')}.tsr",
        file=sys.stderr,
    )
    return OK


def _cmd_ts_apply(args) -> int:
    from .timestamp import apply_timestamp, load_der

    try:
        manifest = load_manifest(args.manifest)
        stamped = apply_timestamp(manifest, load_der(args.token))
    except (RuntimeError, FileNotFoundError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return USAGE
    write_manifest(stamped, args.out or args.manifest)
    print(f"timestamped {args.out or args.manifest} at {stamped['timestamp']['gen_time']}", file=sys.stderr)
    return OK


def _cmd_ts_submit(args) -> int:
    from .timestamp import apply_timestamp, build_request, submit

    try:
        manifest = load_manifest(args.manifest)
        response = submit(build_request(manifest["id"]), args.tsa, timeout=args.timeout)
        stamped = apply_timestamp(manifest, response)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return FAILED
    except (RuntimeError, FileNotFoundError, KeyError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return USAGE
    write_manifest(stamped, args.out or args.manifest)
    print(f"timestamped by {args.tsa} at {stamped['timestamp']['gen_time']}", file=sys.stderr)
    return OK


def _cmd_ts_verify(args) -> int:
    from .timestamp import verify_timestamp

    try:
        manifest = load_manifest(args.manifest)
        cert = Path(args.tsa_cert).read_bytes() if args.tsa_cert else None
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: cannot read manifest: {exc}", file=sys.stderr)
        return USAGE
    ok, message = verify_timestamp(manifest, tsa_cert=cert)
    print(f"timestamp {'OK' if ok else 'FAIL'}: {message}")
    return OK if ok else FAILED


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evidence-seal",
        description="Tamper-evident seals for audit evidence packages.",
    )
    parser.add_argument("--version", action="version", version=f"evidence-seal {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_seal = sub.add_parser("seal", help="seal a directory into a manifest")
    p_seal.add_argument("directory")
    p_seal.add_argument("--out", help="manifest path (default: <dir>.manifest.json alongside)")
    p_seal.add_argument("--prev", help="prior manifest to chain from (records its id as previous)")
    p_seal.add_argument("--meta", action="append", metavar="KEY=VALUE", help="provenance metadata")
    p_seal.add_argument("--ignore", action="append", metavar="GLOB", help="skip matching paths")
    p_seal.add_argument("--sign", metavar="PRIVATE_KEY", help="also sign with an ed25519 key")
    p_seal.set_defaults(func=_cmd_seal)

    p_verify = sub.add_parser("verify", help="verify a directory against its manifest")
    p_verify.add_argument("directory")
    p_verify.add_argument("--manifest", help="manifest path (default: <dir>.manifest.json)")
    p_verify.add_argument("--pubkey", metavar="PEM", help="require a signature by this public key")
    p_verify.add_argument(
        "--tsa-cert", metavar="CERT", help="verify the embedded timestamp against this TSA certificate"
    )
    p_verify.set_defaults(func=_cmd_verify)

    p_chain = sub.add_parser("chain", help="verify manifests link oldest -> newest")
    p_chain.add_argument("manifests", nargs="+", help="manifest files, oldest first")
    p_chain.set_defaults(func=_cmd_chain)

    p_keygen = sub.add_parser("keygen", help="generate an ed25519 keypair")
    p_keygen.add_argument("--private", default="evidence-seal.key")
    p_keygen.add_argument("--public", default="evidence-seal.pub")
    p_keygen.set_defaults(func=_cmd_keygen)

    p_sign = sub.add_parser("sign", help="sign an existing manifest")
    p_sign.add_argument("manifest")
    p_sign.add_argument("--key", required=True, metavar="PRIVATE_KEY")
    p_sign.add_argument("--out", help="write here instead of overwriting the manifest")
    p_sign.set_defaults(func=_cmd_sign)

    _add_timestamp_commands(sub)
    return parser


def _add_timestamp_commands(sub) -> None:
    p_ts = sub.add_parser("timestamp", help="RFC 3161 trusted timestamping of a manifest")
    ts = p_ts.add_subparsers(dest="ts_action", required=True)

    p_req = ts.add_parser("request", help="write a TimeStampReq (.tsq) for the manifest id")
    p_req.add_argument("manifest")
    p_req.add_argument("--out", help="request path (default: <manifest>.tsq)")
    p_req.set_defaults(func=_cmd_ts_request)

    p_apply = ts.add_parser("apply", help="bind a TSA response/token into the manifest")
    p_apply.add_argument("manifest")
    p_apply.add_argument("--token", required=True, metavar="TSR", help="TSA response or token (DER)")
    p_apply.add_argument("--out", help="write here instead of overwriting the manifest")
    p_apply.set_defaults(func=_cmd_ts_apply)

    p_submit = ts.add_parser("submit", help="request, POST to a TSA, and bind in one step")
    p_submit.add_argument("manifest")
    p_submit.add_argument("--tsa", required=True, metavar="URL", help="RFC 3161 TSA endpoint")
    p_submit.add_argument("--timeout", type=float, default=30.0, help="network timeout (seconds)")
    p_submit.add_argument("--out", help="write here instead of overwriting the manifest")
    p_submit.set_defaults(func=_cmd_ts_submit)

    p_tsv = ts.add_parser("verify", help="verify the manifest's embedded timestamp")
    p_tsv.add_argument("manifest")
    p_tsv.add_argument(
        "--tsa-cert", metavar="CERT", help="also verify the token's CMS signature against this cert"
    )
    p_tsv.set_defaults(func=_cmd_ts_verify)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
