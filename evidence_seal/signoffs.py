"""Offline verification of a signed team roster and signed sign-off statements.

An engagement folder (or an extracted deliverable) holds:

- ``team.json`` — the roster: ``{"version": 1, "firm": ..., "members": [{"name",
  "roles", "keys"}]}`` where ``keys`` are OpenSSH ``ssh-ed25519`` public keys.
- ``team.json.sig`` — an SSH signature of the exact ``team.json`` bytes under
  the ``audit-roster@audit-labs`` namespace, made with the firm's key.
- ``signoffs.jsonl`` — one ``{"statement": {...}, "signature": "..."}`` per
  line; the signature covers the canonical JSON of the statement under the
  ``audit-signoff@audit-labs`` namespace.

The firm key is trusted by its fingerprint, which the verifier must obtain
from outside the folder; anything inside the folder can be replaced.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import sshsig

ROSTER_NAMESPACE = "audit-roster@audit-labs"
SIGNOFF_NAMESPACE = "audit-signoff@audit-labs"
ROLES = ("preparer", "reviewer", "partner")
STATEMENT_FIELDS = ("version", "item", "role", "content_hash", "evidence_sha256", "signer", "key", "time")


def canonical(statement: dict) -> bytes:
    """The bytes a statement signature covers."""
    return json.dumps(statement, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def parse_roster(roster_bytes: bytes) -> dict:
    try:
        roster = json.loads(roster_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"team.json is not valid JSON: {exc}") from exc
    if not isinstance(roster, dict) or not isinstance(roster.get("members"), list):
        raise ValueError("team.json must be an object with a 'members' list")  # noqa: TRY004
    names: set[str] = set()
    keys: set[bytes] = set()
    for member in roster["members"]:
        name = str(member.get("name") or "").strip()
        if not name or name.casefold() in names:
            raise ValueError(f"team.json member names must be present and unique: {name!r}")
        names.add(name.casefold())
        if not set(member.get("roles") or []) <= set(ROLES):
            raise ValueError(f"unknown role for {name}: {member.get('roles')}")
        for line in member.get("keys") or []:
            raw = sshsig.parse_public_key(line)
            if raw in keys:
                raise ValueError(f"a key is listed for more than one member ({name})")
            keys.add(raw)
    return roster


def verify_roster(roster_bytes: bytes, signature: str, trusted_fingerprints: set[str]) -> dict:
    """Verify the roster signature and that the signer is a trusted firm key.

    Returns the roster with ``signed_by`` (the firm key fingerprint) added.
    """
    raw = sshsig.verify(roster_bytes, signature, ROSTER_NAMESPACE)
    signer = sshsig.fingerprint(raw)
    if signer not in trusted_fingerprints:
        raise sshsig.SignatureError(f"team.json is signed by {signer}, which is not a trusted firm key")
    roster = parse_roster(roster_bytes)
    roster["signed_by"] = signer
    return roster


def member_for_key(roster: dict, raw_public: bytes) -> dict | None:
    for member in roster.get("members", []):
        for line in member.get("keys") or []:
            if sshsig.parse_public_key(line) == raw_public:
                return member
    return None


def verify_statement(entry: dict, roster: dict) -> dict:
    """Check one sign-off line; returns ``{"ok", "reason", ...statement fields}``."""
    statement = entry.get("statement") if isinstance(entry, dict) else None
    if not isinstance(statement, dict) or any(f not in statement for f in STATEMENT_FIELDS):
        return {"ok": False, "reason": "malformed statement"}
    result = {k: statement.get(k) for k in STATEMENT_FIELDS}
    try:
        raw = sshsig.verify(canonical(statement), str(entry.get("signature") or ""), SIGNOFF_NAMESPACE)
        if sshsig.parse_public_key(statement["key"]) != raw:
            return {**result, "ok": False, "reason": "statement key does not match the signing key"}
    except sshsig.SignatureError as exc:
        return {**result, "ok": False, "reason": str(exc)}
    member = member_for_key(roster, raw)
    if member is None:
        return {**result, "ok": False, "reason": "signing key is not in the roster"}
    if statement["signer"] != member["name"]:
        return {**result, "ok": False, "reason": f"key belongs to {member['name']}, not {statement['signer']}"}
    if statement["role"] not in (member.get("roles") or []):
        return {**result, "ok": False, "reason": f"{member['name']} does not hold the {statement['role']} role"}
    return {**result, "ok": True, "reason": "", "fingerprint": sshsig.fingerprint(raw)}


def summarize(results: list[dict]) -> dict[str, dict[str, dict]]:
    """Group valid statements by item and content hash; a version is complete when a
    preparer and a reviewer who is a different person both signed it."""
    items: dict[str, dict[str, dict]] = {}
    for res in results:
        if not res.get("ok"):
            continue
        version = items.setdefault(res["item"], {}).setdefault(
            res["content_hash"], {"preparers": [], "reviewers": [], "complete": False}
        )
        bucket = "preparers" if res["role"] == "preparer" else "reviewers"
        if res["signer"] not in version[bucket]:
            version[bucket].append(res["signer"])
    for versions in items.values():
        for version in versions.values():
            version["complete"] = bool(version["preparers"]) and any(
                r not in version["preparers"] for r in version["reviewers"]
            )
    return items


def read_signoffs(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    entries = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"signoffs.jsonl line {line_no} is not valid JSON: {exc}") from exc
    return entries


def verify_folder(folder: str | Path, trusted_fingerprints: set[str]) -> dict:
    """Verify ``team.json``, ``team.json.sig``, and ``signoffs.jsonl`` in *folder*."""
    folder = Path(folder)
    roster_path, sig_path = folder / "team.json", folder / "team.json.sig"
    if not roster_path.is_file() or not sig_path.is_file():
        raise FileNotFoundError("team.json and team.json.sig are required")
    roster = verify_roster(
        roster_path.read_bytes(), sig_path.read_text(encoding="utf-8"), trusted_fingerprints
    )
    results = [verify_statement(e, roster) for e in read_signoffs(folder / "signoffs.jsonl")]
    return {
        "firm": roster.get("firm", ""),
        "roster_signed_by": roster["signed_by"],
        "statements": results,
        "invalid": sum(1 for r in results if not r["ok"]),
        "items": summarize(results),
    }
