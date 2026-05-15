"""Streaming SHA-256 helpers for file integrity checks (stdlib only)."""

from __future__ import annotations

import hashlib
import sys

# Read files in 1 MiB chunks for hashing (spec requirement).
CHUNK_SIZE = 1 << 20


def hash_file(filepath: str) -> str:
    """Read *filepath* in 1 MB chunks and return the SHA-256 hex digest."""
    digest = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def verify_files_match(path_a: str, path_b: str) -> bool:
    """Return True if *path_a* and *path_b* have identical SHA-256 digests.

    Raises ValueError with a clear message if the digests differ.
    """
    digest_a = hash_file(path_a)
    digest_b = hash_file(path_b)
    if digest_a != digest_b:
        raise ValueError(
            f"SHA-256 mismatch between {path_a!r} and {path_b!r}: "
            f"{digest_a} != {digest_b}"
        )
    return True


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(
            f"usage: {sys.argv[0]} <file_a> <file_b>",
            file=sys.stderr,
        )
        sys.exit(2)
    try:
        verify_files_match(sys.argv[1], sys.argv[2])
    except ValueError as exc:
        print(exc, file=sys.stderr)
        sys.exit(1)
    print("Match: True")
