"""File hashing and a Merkle root over a set of files.

The Merkle root condenses a whole package into one hash. Two packages with the
same root are byte-identical in content and layout; any change to any file — or
to the set of files — changes the root.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

_CHUNK = 1 << 20  # 1 MiB streaming reads keep memory flat on large evidence


def hash_file(path: str | Path) -> str:
    """Return the SHA-256 hex digest of a file, read in streaming chunks."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_bytes(data: bytes) -> str:
    """Return the SHA-256 hex digest of a bytes object."""
    return hashlib.sha256(data).hexdigest()


def _leaf(path: str, file_hash: str) -> str:
    # Bind the path into the leaf so renaming a file changes the root even when
    # its contents are unchanged. A domain prefix separates leaves from nodes.
    return hashlib.sha256(f"leaf:{path}\x00{file_hash}".encode()).hexdigest()


def _pair(left: str, right: str) -> str:
    return hashlib.sha256(f"node:{left}{right}".encode()).hexdigest()


def merkle_root(entries: dict[str, str]) -> str:
    """Compute a Merkle root from a ``{path: file_hash}`` mapping.

    Leaves are ordered by path so the root is deterministic regardless of
    filesystem iteration order. An empty package has a well-defined empty root.
    """
    if not entries:
        return hashlib.sha256(b"empty").hexdigest()

    level = [_leaf(path, file_hash) for path, file_hash in sorted(entries.items())]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])  # duplicate the last node on an odd level
        level = [_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]
