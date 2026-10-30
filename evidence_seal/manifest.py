"""Build, load, and verify evidence manifests, and verify seal chains.

A manifest is a JSON object describing a sealed directory: every file's SHA-256,
a Merkle ``root`` over them, provenance metadata, and a ``previous`` link to an
earlier manifest's id. Its own ``id`` is the SHA-256 of its canonical form
(excluding ``id`` and ``signature``), so the manifest is self-verifying and can
be chained.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import ALGORITHM, MANIFEST_VERSION, __version__
from .hashing import hash_bytes, hash_file, merkle_root

# Keys excluded from the canonical bytes the id is computed over. The id cannot
# cover itself; a signature and a timestamp are both applied *to* the id
# afterwards, so they sit outside it and compose independently of each other.
_ID_EXCLUDED = ("id", "signature", "timestamp")


def iter_files(
    directory: Path, ignore: list[str] | None, exclude: set[str]
) -> list[tuple[str, Path]]:
    """Return ``(posix_relpath, abspath)`` for every file under *directory*.

    Paths matching an *ignore* glob (against the relative path) or present in
    *exclude* are skipped. Results are sorted by relative path.
    """
    ignore = ignore or []
    out: list[tuple[str, Path]] = []
    for path in directory.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(directory).as_posix()
        if rel in exclude or any(fnmatch.fnmatch(rel, pat) for pat in ignore):
            continue
        out.append((rel, path))
    out.sort(key=lambda pair: pair[0])
    return out


def canonical_bytes(manifest: dict, exclude: tuple[str, ...] = _ID_EXCLUDED) -> bytes:
    """Serialize a manifest deterministically for hashing or signing."""
    trimmed = {k: v for k, v in manifest.items() if k not in exclude}
    return json.dumps(trimmed, sort_keys=True, separators=(",", ":")).encode()


def compute_id(manifest: dict) -> str:
    """The manifest's self-id: SHA-256 of its canonical form."""
    return hash_bytes(canonical_bytes(manifest))


def build_manifest(
    directory: str | Path,
    metadata: dict | None = None,
    previous: str | None = None,
    ignore: list[str] | None = None,
    exclude: set[str] | None = None,
) -> dict:
    """Seal *directory* into a manifest dict (id included, unsigned)."""
    directory = Path(directory)
    if not directory.is_dir():
        raise FileNotFoundError(f"not a directory: {directory}")

    files = iter_files(directory, ignore, exclude or set())
    entries = [
        {"path": rel, ALGORITHM: hash_file(abs_path), "bytes": abs_path.stat().st_size}
        for rel, abs_path in files
    ]
    hashes = {entry["path"]: entry[ALGORITHM] for entry in entries}

    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "algorithm": ALGORITHM,
        "tool": f"evidence-seal/{__version__}",
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "subject": directory.name,
        "previous": previous,
        "metadata": dict(sorted((metadata or {}).items())),
        "ignore": sorted(ignore or []),
        "file_count": len(entries),
        "total_bytes": sum(entry["bytes"] for entry in entries),
        "root": merkle_root(hashes),
        "files": entries,
    }
    manifest["id"] = compute_id(manifest)
    return manifest


def write_manifest(manifest: dict, path: str | Path) -> None:
    """Write a manifest as pretty JSON (stable key order)."""
    Path(path).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_manifest(path: str | Path) -> dict:
    """Load a manifest JSON file."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


@dataclass
class VerifyResult:
    """The outcome of verifying a directory against its manifest."""

    modified: list[str] = field(default_factory=list)
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    id_ok: bool = True
    root_ok: bool = True
    checked: int = 0

    @property
    def intact(self) -> bool:
        """True only if nothing drifted and the manifest is internally sound."""
        drifted = self.modified or self.added or self.removed
        return not drifted and self.id_ok and self.root_ok


def verify_manifest(
    directory: str | Path,
    manifest: dict,
    ignore: list[str] | None = None,
    exclude: set[str] | None = None,
) -> VerifyResult:
    """Compare the current contents of *directory* against *manifest*."""
    directory = Path(directory)
    recorded = {entry["path"]: entry[ALGORITHM] for entry in manifest.get("files", [])}

    result = VerifyResult()
    # The manifest is only trustworthy if its id and root re-derive.
    result.id_ok = compute_id(manifest) == manifest.get("id")
    result.root_ok = merkle_root(recorded) == manifest.get("root")

    present: dict[str, str] = {}
    for rel, abs_path in iter_files(directory, ignore, exclude or set()):
        present[rel] = hash_file(abs_path)

    result.checked = len(present)
    for rel, digest in present.items():
        if rel not in recorded:
            result.added.append(rel)
        elif recorded[rel] != digest:
            result.modified.append(rel)
    result.removed = [rel for rel in recorded if rel not in present]

    for bucket in (result.modified, result.added, result.removed):
        bucket.sort()
    return result


@dataclass
class ChainResult:
    """The outcome of verifying a sequence of chained manifests."""

    ok: bool
    length: int
    broken_at: int | None = None  # index whose `previous` did not match
    reason: str = ""


def verify_chain(manifests: list[dict]) -> ChainResult:
    """Verify manifests link oldest→newest via ``previous`` == prior ``id``.

    Also checks that each manifest's own id re-derives, so a tampered link in
    the middle is caught whether the break is in the pointer or the content.
    """
    if not manifests:
        return ChainResult(ok=False, length=0, reason="no manifests given")

    for index, manifest in enumerate(manifests):
        if compute_id(manifest) != manifest.get("id"):
            return ChainResult(False, len(manifests), index, "manifest id does not re-derive")
        expected_prev = manifests[index - 1]["id"] if index else None
        if manifest.get("previous") != expected_prev:
            reason = (
                "first manifest should have no previous"
                if index == 0
                else "previous does not match the prior manifest id"
            )
            return ChainResult(False, len(manifests), index, reason)

    return ChainResult(ok=True, length=len(manifests))
